import { Octokit, App } from "octokit";
import libsodium from 'libsodium-wrappers';
import tar from "tar";

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import vaultClient from "node-vault";
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


type Secrets = {
    githubKey: string;
    sonatypeLogin: string;
    sonatypePassword: string;
    sonatypeEmail: string;
    nugetToken: string;
}
async function readVault(): Promise<Secrets> {
    const endpoint = process.env.VAULT_ADDR ?? "";
    if (endpoint.length == 0) {
        panic("VAULT_ADDR variable is unset");
    }
    const vault = vaultClient({
        apiVersion: "v1",
        endpoint: endpoint,
    });

    vault.token = process.env.VAULT_TOKEN ?? "";
    if (vault.token.length == 0) {
        panic("VAULT_TOKEN variable is unset");
    }

    const sonatype = await vault.read("secret/sonatype");
    return {
        sonatypeLogin: sonatype.data.user,
        sonatypePassword: sonatype.data.password,
        sonatypeEmail: sonatype.data.email,
        githubKey: (await vault.read("secret/github")).data.token,
        nugetToken: (await vault.read("secret/nuget")).data.token,
    }
};

async function readSecret(name: string) {
    const out = await inquirer.prompt([
        {
            type: 'password',
            name: 'secret',
            message: `Enter ${name}:`,
            mask: '*',
        }
    ]);
    return out.secret;
}

async function readInput(name: string) {
    const out = await inquirer.prompt([
        {
            type: 'input',
            name: 'input',
            message: `Enter ${name}:`,
        }
    ]);
    return out.input;
}
async function readSecrets(sonatype: boolean, nuget: boolean): Promise<Secrets> {

    var sonatypeUser = "";
    var sonatypeEmail = "";
    var sonatypePassword = "";

    var nugetToken = "";

    const githubKey = await readSecret("Github Token");

    if (sonatype) {
        sonatypeUser = await readInput("Sonatype Username");
        sonatypeEmail = await readInput("Sonatype email");
        sonatypePassword = await readSecret("Sonatype Password");
    }
    if (nuget) {
        nugetToken = await readSecret("Nuget Token");
    }
    return {
        sonatypeLogin: sonatypeUser,
        sonatypePassword: sonatypePassword,
        sonatypeEmail: sonatypeEmail,
        githubKey: githubKey,
        nugetToken: nugetToken,
    }
};


type Repo = {
    owner: string,
    repo: string,
}

function makeEnv(secrets: Secrets, repo: Repo) {
    return {
        octokit: new Octokit({ auth: secrets.githubKey }),
        sodium: libsodium,
        repo: repo,
        secrets: secrets,
        eKey: crypto.randomBytes(32).toString("hex"),
        eIv: crypto.randomBytes(16).toString("hex"),
        gpgPassphrase: crypto.randomBytes(32).toString("hex"),
        tmpDir: fs.mkdtempSync(path.join(os.tmpdir(), "publisher-out-")),
        tmpGpg: fs.mkdtempSync(path.join(os.tmpdir(), "publisher-gpg-home-")),
        tmpOut: path.join(os.tmpdir(), `pub-out-${crypto.randomBytes(16).toString("hex")}.tar.gz`),
        tmpEnc: path.join(os.tmpdir(), `pub-out-${crypto.randomBytes(16).toString("hex")}.tar.gz.enc`),
        gpgBase: '.secrets/gnupg/',
        pubring: function () {
            return `${this.gpgBase}/pubring.gpg`;
        },
        secring: function () {
            return `${this.gpgBase}/secring.gpg`;
        },
    };
}

type Env = ReturnType<typeof makeEnv>;

type RepoPubKey = { key_id: string; key: string };

async function getRepoKey(env: Env): Promise<RepoPubKey> {
    const out = await env.octokit.rest.actions.getRepoPublicKey(env.repo);
    assert(out.status == 200, "repo key");
    return out.data;
}

async function setupSecret(rpk: RepoPubKey, secretId: string, secretVal: string, env: Env) {
    const esec = await env.sodium.ready.then(() => {
        let binkey = env.sodium.from_base64(rpk.key, env.sodium.base64_variants.ORIGINAL)
        let binsec = env.sodium.from_string(secretVal)
        let encBytes = env.sodium.crypto_box_seal(binsec, binkey)
        let output = env.sodium.to_base64(encBytes, env.sodium.base64_variants.ORIGINAL)
        return output
    });
    try {
        await env.octokit.rest.actions.deleteRepoSecret({ ...env.repo, secret_name: secretId });
    } catch (e) {
        console.log(`Can't remove ${secretId}: ${e}`);
    }
    const out = await env.octokit.rest.actions.createOrUpdateRepoSecret({ ...env.repo, secret_name: secretId, encrypted_value: esec, key_id: rpk.key_id });
    assert(out.status == 201, `Can't upload ${secretId}`);
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

async function setupSbtSonatype(env: Env) {
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

        const creds = stripLeadingWhitespace(`realm=Sonatype Nexus Repository Manager
        host=oss.sonatype.org
        user=${env.secrets.sonatypeLogin}
        password=${env.secrets.sonatypePassword}`);
        fs.writeFileSync(path.join(env.tmpDir, ".secrets", "credentials.sonatype-nexus.properties"), creds);

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

        const data = fs.readFileSync(env.tmpEnc);
        const content = Buffer.from(data).toString('base64');

        const target = "secrets.tar.enc";
        var sha: string | undefined = ""
        try {
            const data = await env.octokit.request(`GET /repos/{owner}/{repo}/contents/{file_path}`, {
                ...env.repo,
                file_path: target,
            });
            sha = data.data.sha;
        } catch (e) {
            sha = undefined;
        }


        console.debug(sha);
        await env.octokit.rest.repos.createOrUpdateFileContents({
            ...env.repo,
            path: target,
            message: `Secrets updated by https://github.com/7mind/ghpub`,
            content: content,
            sha: sha,
        })

        const rpk = await getRepoKey(env);
        await setupSecret(rpk, "OPENSSL_KEY", env.eKey, env);
        await setupSecret(rpk, "OPENSSL_IV", env.eIv, env);

        const keys = (await run("gpg", ["--homedir", env.tmpGpg, "--list-keys", "--with-colons"])).split('\n').map(line => line.split(":")).filter(line => line[0] == "fpr").map(line => line[9]);

        const servers = ["keys.openpgp.org", "keyserver.ubuntu.com", "pgp.mit.edu"];
        console.log(`Going to upload ${keys} to ${servers}`);

        for (let key in keys) {
            for (let server in servers) {
                await run("gpg", ["--homedir", env.tmpGpg, "--send-keys", "--keyserver", servers[server], keys[key]]);
            }
        }

        fs.rmSync(env.tmpDir, { recursive: true });
        fs.rmSync(env.tmpGpg, { recursive: true });
        fs.rmSync(env.tmpOut);
        fs.rmSync(env.tmpEnc);
    } catch (e) {
        console.log(e);
    }
}

async function setupNuget(env: Env) {
    const rpk = await getRepoKey(env);
    await setupSecret(rpk, "NUGET_TOKEN", env.secrets.nugetToken, env);
}
async function main() {
    const argv = await yargs(hideBin(process.argv)).options({
        owner: { type: 'string', demandOption: true },
        repo: { type: 'string', demandOption: true },
        useVault: { type: 'boolean', default: true },
        setupSonatype: { type: 'boolean', default: true },
        setupNuget: { type: 'boolean', default: true },
    }).argv;

    const repo = {
        owner: argv.owner,
        repo: argv.repo,
    }

    console.log(`* Will operate on ${JSON.stringify(repo)}`);

    if (argv.setupSonatype) {
        console.log("* Will commit encrypted Sonatype secrets archive");
        console.log("* Will add decryption tokens into Github secrets");
    }
    if (argv.setupNuget) {
        console.log("* Will add Nuget token into Github secrets");
    }

    const response = await inquirer.prompt([
        {
            type: 'confirm',
            name: 'continue',
            message: 'Continue?'
        }
    ]);

    if (!response.continue) {
        process.exit(0)
    }

    const secrets = await (() => {
        if (argv.useVault) {
            return readVault();
        } else {
            return readSecrets(argv.setupSonatype, argv.setupNuget);
        }
    })();

    console.debug(secrets);
    process.exit(1);
    const env = makeEnv(secrets, repo);
    if (argv.setupSonatype) {
        console.log("Setting up sonatype secrets...")
        await setupSbtSonatype(env);
    }
    if (argv.setupNuget) {
        console.log("Adding nuget key...")
        await setupNuget(env);
    }
}

main()
