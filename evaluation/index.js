#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const hkdf = require('futoin-hkdf');
const Chance = require('chance');
const WebCrypto = require('node-webcrypto-ossl');
const stringify = require('json-stable-stringify');
const crypto = new WebCrypto();

if (process.argv.length !== 5) {
    console.error(`Usage: ${process.argv[0]} ${process.argv[1]} CONFIG.json SEED #RESPONSES`);
    process.exit(1);
}

const configFile = path.resolve(process.argv[2]);
const seed = process.argv[3];
const repititions = parseInt(process.argv[4]);

if (!(repititions && repititions > 0)) {
    console.error('Error: invalid number of responses');
    process.exit(1);
}

const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
if (!config.ethicsKey || !config.studyExample || !config.platformURL) {
    console.error('Error: invalid config file');
    process.exit(1);
}

console.log(`Evaluation ${new Date().toJSON()}:`);
console.log(`   seed=${seed}`);
console.log(`   #responses=${repititions}`);
console.log(`   config=${configFile}`);

const chance = new Chance(seed);
const k = config.ethicsKey;
const BASE_URL = config.platformURL;
const studyExample = config.studyExample;

function signatureToASN1(signature) {
    let r = Buffer.concat([Buffer.alloc(1), signature.slice(0, 32)]);
    while (r.readUInt8(0) === 0 && r.readInt8(1) > 0) {
        r = r.slice(1);
    }

    let s = Buffer.concat([Buffer.alloc(1), signature.slice(32, 64)]);
    while (s.readUInt8(0) === 0 && s.readInt8(1) > 0) {
        s = s.slice(1);
    }

    const asn1 = Buffer.alloc(6 + r.length + s.length);
    asn1.writeUInt8(0x30, 0);
    asn1.writeUInt8(asn1.length - 2, 1);
    asn1.writeUInt8(0x02, 2);
    asn1.writeUInt8(r.length, 3);
    asn1.writeUInt8(0x02, 4 + r.length);
    asn1.writeUInt8(s.length, 5 + r.length);
    r.copy(asn1, 4);
    s.copy(asn1, 6 + r.length);

    return asn1;
}

async function createStudy() {
    const study = {...studyExample};

    const keypair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const pk = Buffer.from(await crypto.subtle.exportKey('raw', keypair.publicKey)).toString('base64');
    study.researcher_identity = pk;

    const data = Buffer.from(stringify(studyExample));
    const signature = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, keypair.privateKey, data));
    const asn1 = signatureToASN1(signature);
    study.researcher_signature = asn1.toString('base64');

    const response = await axios.post(`${BASE_URL}/studies`, study);
    return {
        id: response.data.id,
        privateKey: keypair.privateKey
    };
}

async function completeStudy(studyId, researcherPrivateKey) {
    const study = await axios.get(`${BASE_URL}/studies/${studyId}`);
    const data = Buffer.from(study.data.public_key, 'base64');
    const signature = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, researcherPrivateKey, data));
    const asn1 = signatureToASN1(signature);

    const times = [];
    times.push(process.hrtime.bigint());
    const response = await axios.post(`${BASE_URL}/studies/${studyId}/complete`, { auth: asn1.toString('base64') });
    times.push(process.hrtime.bigint());

    return {
        results: response.data,
        time: normalize(times)[0]
    };
}

async function approveStudy(studyId) {
    const study = await axios.get(`${BASE_URL}/studies/${studyId}`, { transformResponse: d => d });

    const sk = await crypto.subtle.importKey('jwk', { kty: k.kty, crv: k.crv, key_ops: ['sign'], d: k.d, x: k.x, y: k.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const pk = await crypto.subtle.importKey('jwk', { kty: k.kty, crv: k.crv, x: k.x, y: k.y }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);

    const data = Buffer.from(study.data);
    const cert = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, sk, data));
    const asn1 = signatureToASN1(cert);

    await axios.put(`${BASE_URL}/studies/${studyId}`, {
        pk: Buffer.from((await crypto.subtle.exportKey('raw', pk))).toString('base64'),
        cert: Buffer.from(asn1).toString('base64')
    });
}

async function submitRandomResponse(studyId) {
    const times = [];
    const study = await axios.get(`${BASE_URL}/studies/${studyId}`);

    // generate random response
    const data = {};
    for (const page of study.data.questionnaire.pages) {
        for (const question of page.questions) {
            switch (question.type) {
                case "text": {
                    data[question.name] = chance.string();

                    if (question.validators && question.validators.length > 0) {
                        switch (question.validators[0].type) {
                            case 'numeric':
                                data[question.name] = chance.integer({
                                    min: question.validators[0].minValue,
                                    max: question.validators[0].maxValue
                                });
                                break;
                        }
                    }

                    break;
                }

                case "matrix": {
                    const tmp = {};

                    for (const row of question.rows) {
                        tmp[row.value] = chance.pickone(question.columns).value;
                    }

                    data[question.name] = tmp;
                    break;
                }
            }
        }
    }

    times.push(process.hrtime.bigint());
    const response = await axios.post(`${BASE_URL}/studies/${studyId}`, {});
    times.push(process.hrtime.bigint());
    const submissionId = response.data.id;
    const peer = Buffer.from(response.data.pk, 'base64');

    const key = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']);
    const ownPublicKey = Buffer.from(await crypto.subtle.exportKey('raw', key.publicKey));
    const peerPublicKey = await crypto.subtle.importKey('raw', peer, { name: 'ECDH', namedCurve: 'P-256' }, false, []);

    const info = new Uint8Array(130);
    info.set(peer, 0);
    info.set(ownPublicKey, 65);

    const keyMaterial = await crypto.subtle.deriveBits({ name: 'ECDH', namedCurve: 'P-256', public: peerPublicKey }, key.privateKey, 256);
    const sharedKey = hkdf(keyMaterial, 32, {
        salt: false,
        info: info,
        hash: 'SHA-512'
    });

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = Buffer.from(JSON.stringify(data));
    const importedKey = await crypto.subtle.importKey('raw', sharedKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: Buffer.from(nonce) }, importedKey, plaintext);

    times.push(process.hrtime.bigint());
    const submission = await axios.put(`${BASE_URL}/studies/${studyId}/${submissionId}`, {
        pk: ownPublicKey.toString('base64'),
        response: Buffer.from(encrypted).toString('base64'),
        nonce: Buffer.from(nonce).toString('base64')
    });
    times.push(process.hrtime.bigint());

    if (submission.data.ok !== true) {
        throw new '';
    }

    return normalize(times);
}

function normalize(arr) {
    const res = [];

    for (let i = 1; i < arr.length; i += 1) {
        res[i - 1] = (arr[i] - arr[i - 1]).toString();
    }

    return res;
}

async function evaluate() {
    try {
        console.log('create study...');
        const { id, privateKey } = await createStudy();
        console.log(`study ${id} created!`);
        console.log();

        console.log('approve study...');
        await approveStudy(id);
        console.log('study approved!');
        console.log();

        console.log(`submit ${repititions} responses...`);
        for (let i = 0; i < repititions; i += 1) {
            const times = await submitRandomResponse(id);
            console.log(`${i},${times.join(',')}`);
        }
        console.log(`${repititions} responses submitted!`);
        console.log();

        console.log('complete study...');
        const { results, time } = await completeStudy(id, privateKey);
        console.log(`   result=${JSON.stringify(results)}`);
        console.log(`   time=${time}`);
        console.log('study completed!');
    } catch (e) {
        console.error('[eval error]', e.message);
    }
}

evaluate();
