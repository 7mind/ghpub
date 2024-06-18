import tar from "tar";

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import yargs, { exit } from 'yargs';
import { hideBin } from 'yargs/helpers';
import inquirer from "inquirer";

type Assert = (condition: unknown, clue: string) => asserts condition;
const assert: Assert = (condition, clue) => {
    if (condition == false) throw `Invalid assertion: ${clue}`;
};

function stripLeadingWhitespace(multilineString: string): string {
    return multilineString.split('\n').map(line => line.replace(/^\s+/, '')).join('\n');
}

function panic(clue: string) {
    console.error(clue);
    process.exit(1);
}

async function run(cmd: string, args: Array<string>) {
    return new Promise<string>((resolve, reject) => {
        console.debug(`> ${cmd} ${args.join(" ")}`);
        const enc = spawn(cmd, args);

        const output = [] as string[]

        enc.stdout.on('data', (data) => {
            output.push(data.toString())
        });

        enc.on('close', (code) => {
            if (code == 0) {
                resolve(output.join('').trim())
            } else {
                reject(`${cmd} failed with code ${code}`)
            }
        });
    });
}


async function setupSbtSonatype(env) {
    try {
        const gpgBase = path.join(env.tmpDir, env.gpgBase);
        fs.mkdirSync(gpgBase, { recursive: true });

        const localSbt = stripLeadingWhitespace(`pgpPassphrase := Some("${env.gpgPassphrase}".toCharArray)
                        pgpSecretRing := file("${env.secring()}")
                        pgpPublicRing := file("${env.pubring()}")
                        useGpg := false`);
        fs.writeFileSync(path.join(env.tmpDir, "local.sbt"), localSbt);

        const gpgConf = stripLeadingWhitespace(`%echo Generating a basic OpenPGP key
                    Key-Type: RSA
                    Key-Length: 2048
                    Key-Usage: encrypt,sign,auth
                    Name-Real: ${env.repo.owner}
                    Name-Comment: ${env.repo.owner}'s ephemeral Sonatype publishing key
                    Name-Email: ${env.secrets.sonatypeEmail}
                    Expire-Date: 0
                    Passphrase: ${env.gpgPassphrase}
                    %commit
                    %echo done`);
        const tmpGpgConf = path.join(os.tmpdir(), `pub-gpg-${crypto.randomBytes(16).toString("hex")}.txt`);
        fs.writeFileSync(tmpGpgConf, gpgConf);

        // const creds = stripLeadingWhitespace(`realm=Sonatype Nexus Repository Manager
        // host=oss.sonatype.org
        // user=${env.secrets.sonatypeLogin}
        // password=${env.secrets.sonatypePassword}`);
        // fs.writeFileSync(path.join(env.tmpDir, ".secrets", "credentials.sonatype-nexus.properties"), creds);

        await run("gpgconf", ["--reload", "gpg-agent"]);
        await run("gpg", ["--homedir", env.tmpGpg, "--batch", "--full-generate-key", tmpGpgConf]);

        await run("gpg", ["--homedir", env.tmpGpg, "--batch", "--yes", "--passphrase", env.gpgPassphrase, "--pinentry-mode", "loopback", "--export-secret-keys", "--output", path.join(env.tmpDir, env.secring())]);
        await run("gpg", ["--homedir", env.tmpGpg, "--batch", "--yes", "--passphrase", env.gpgPassphrase, "--pinentry-mode", "loopback", "--export", "--output", path.join(env.tmpDir, env.pubring())]);

        await new Promise<void>((resolve, reject) => {
            const task = tar.c(
                {
                    gzip: true,
                    portable: true,
                    cwd: env.tmpDir,
                },
                ["."]
            ).pipe(fs.createWriteStream(env.tmpOut))

            task.once('error', reject);
            task.once('finish', resolve);
        });

        await run("openssl", ["aes-256-cbc", "-K", env.eKey, "-iv", env.eIv, "-in", env.tmpOut, "-out", env.tmpEnc]);



        const keys = (await run("gpg", ["--homedir", env.tmpGpg, "--list-keys", "--with-colons"])).split('\n').map(line => line.split(":")).filter(line => line[0] == "fpr").map(line => line[9]);

        //const servers = ["keyserver.ubuntu.com", "pgp.mit.edu", "keys.openpgp.org"];
        const servers = ["keyserver.ubuntu.com"];

        console.log(`Going to upload ${keys} to ${servers}`);

        var count = 0
        for (let key in keys) {
            for (let server in servers) {
                try {
                    await run("gpg", ["--homedir", env.tmpGpg, "--send-keys", "--keyserver", servers[server], keys[key]]);
                    count += 1
                } catch (e) {
                    console.log(`Failed to upload key to ${server} but that's not critical`)
                }
            }
        }
        if (count > 0) {
            console.log("The GPG key is uploaded to at least one server, continuing")
        } else {
            panic("Failed to upload GPG key to any of the servers")
        }

        console.log("...done")


        // fs.rmSync(env.tmpDir, { recursive: true });
        // fs.rmSync(env.tmpGpg, { recursive: true });
        // fs.rmSync(env.tmpOut);
        // fs.rmSync(env.tmpEnc);
    } catch (e) {
        console.log(e);
    }
}


async function main() {
    var opts = {};
    const argv = await yargs(hideBin(process.argv)).options({
        owner: { type: 'string', demandOption: true },
        email: { type: 'string', demandOption: true },
    }).options(opts).argv;

    const env = {
        eKey: crypto.randomBytes(32).toString("hex"),
        eIv: crypto.randomBytes(16).toString("hex"),
        gpgPassphrase: crypto.randomBytes(32).toString("hex"),
        tmpDir: fs.mkdtempSync(path.join(os.tmpdir(), "publisher-out-")),
        tmpGpg: fs.mkdtempSync(path.join(os.tmpdir(), "publisher-gpg-home-")),
        tmpOut: path.join(os.tmpdir(), `pub-out-${crypto.randomBytes(16).toString("hex")}.tar.gz`),
        tmpEnc: path.join(os.tmpdir(), `pub-out-${crypto.randomBytes(16).toString("hex")}.tar.gz.enc`),
        // tmpEnc: `secrets.tar.gz.enc`,
        gpgBase: '.secrets/gnupg',
        pubring: function () {
            return `${this.gpgBase}/pubring.gpg`;
        },
        secring: function () {
            return `${this.gpgBase}/secring.gpg`;
        },
        secrets: {
            sonatypeEmail: argv.email,
        },
        repo: {
            owner: argv.owner,
        }
    };
    console.log(`OPENSSL_KEY=${env.eKey}`);
    console.log(`OPENSSL_IV=${env.eIv}`);
    console.log(`output   : ${env.tmpOut}`);
    console.log(`encrypted: ${env.tmpEnc}`);
    await setupSbtSonatype(env);
}

main()
