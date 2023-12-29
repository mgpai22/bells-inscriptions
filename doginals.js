#!/usr/bin/env node

const dogecore = require('./bitcore-lib-bells')
const axios = require('axios')
const fs = require('fs')
const dotenv = require('dotenv')
const mime = require('mime-types')
const express = require('express')

const { PrivateKey, Address, Transaction, Script, Opcode } = dogecore
const { Hash, Signature } = dogecore.crypto
var hex = function(hex) {return new Buffer(hex, 'hex');};


dotenv.config()

if (process.env.TESTNET === 'true') {
    dogecore.Networks.defaultNetwork = dogecore.Networks.testnet
}

const bellsnet = {
    name: 'livenet',
    addressVersion: 0x1E,
    magic: hex('c0c0c0c0'),
    genesisBlock: {
      height: 0,
      nonce: 44481,
      version: 1,
      hash: hex('e5be24df57c43a82d15c2f06bda961296948f8f8eb48501bed1efb929afe0698'),
      prev_hash: Buffer.alloc(32, 0),
      timestamp: 1383509530,
      merkle_root: hex('5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69'),
      bits: 0x1e0ffff0
    },
    addressPubkey: 25,
    addressScript: 30,
    bip32public: 0x0488b21e,
    bip32private: 0x0488ade4,
    keySecret: 153,
  };
  
  //dogecore.Networks.add(bellsnet);




if (process.env.FEE_PER_KB) {
    Transaction.FEE_PER_KB = parseInt(process.env.FEE_PER_KB)
} else {
    Transaction.FEE_PER_KB = 100000
}

const WALLET_PATH = process.env.WALLET || '.wallet.json'


async function main() {
    let cmd = process.argv[2]

    if (fs.existsSync('pending-txs.json')) {
        console.log('found pending-txs.json. rebroadcasting...')
        const txs = JSON.parse(fs.readFileSync('pending-txs.json'))
        await broadcastAll(txs.map(tx => new Transaction(tx)), false)
        return 
    }

    if (cmd == 'mint') {
        await mint()
    } else if (cmd == 'wallet') {
        await wallet()
    } else if (cmd == 'server') {
        await server()
    } else {
        throw new Error(`unknown command: ${cmd}`)
    }
}


async function wallet() {
    let subcmd = process.argv[3]

    if (subcmd == 'new') {
        console.log('generating new wallet')
        walletNew()
    } else if (subcmd == 'sync') {
        await walletSync()
    } else if (subcmd == 'balance') {
        walletBalance()
    } else if (subcmd == 'send') {
        await walletSend()
    } else if (subcmd == 'split') {
        await walletSplit()
    } else {
        throw new Error(`unknown subcommand: ${subcmd}`)
    }
}


function walletNew() {
    if (!fs.existsSync(WALLET_PATH)) {
        const privateKey = new PrivateKey()
        const privkey = privateKey.toWIF()
        console.log('fuck')

        const address = privateKey.toAddress().toString()
        console.log('fuck2')
        const json = { privkey, address, utxos: [] }
        fs.writeFileSync(WALLET_PATH, JSON.stringify(json, 0, 2))
        console.log('address', address)
    } else {
        throw new Error('wallet already exists')
    }
}


async function walletSync() {
    if (process.env.TESTNET == 'true') throw new Error('no testnet api')

    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    console.log('syncing utxos with dogechain.info api')

    // let response = await axios.get(`https://bells.quark.blue/api/address/${wallet.address}/utxo`)
    // console.log('response', response.data)
    // wallet.utxos = response.data.unspent_outputs.map(output => {
    //     return {
    //         txid: output.tx_hash,
    //         vout: output.tx_output_n,
    //         script: output.script,
    //         satoshis: output.value
    //     }
    // })

    let response = await axios.get(`https://bells.quark.blue/api/address/${wallet.address}/utxo`);
console.log('response', response.data);

wallet.utxos = await Promise.all(response.data.map(async (utxo) => {
    let txResponse = await axios.get(`https://bells.quark.blue/api/tx/${utxo.txid}`);
    console.log('txResponse', txResponse.data);
    let transaction = txResponse.data;
    let voutData = transaction.vout[utxo.vout];

    return {
        txid: utxo.txid,
        vout: utxo.vout,
        script: voutData ? voutData.scriptpubkey : undefined,
        satoshis: utxo.value
    };
}));

    fs.writeFileSync(WALLET_PATH, JSON.stringify(wallet, 0, 2))

    let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)

    console.log('balance', balance)
}


function walletBalance() {
    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)

    console.log(wallet.address, balance)
}


async function walletSend() {
    const argAddress = process.argv[4]
    const argAmount = process.argv[5]

    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
    if (balance == 0) throw new Error('no funds to send')

    let receiver = new Address(argAddress)
    let amount = parseInt(argAmount)

    let tx = new Transaction()
    if (amount) {
        tx.to(receiver, amount)
        fund(wallet, tx)
    } else {
        tx.from(wallet.utxos)
        tx.change(receiver)
        tx.sign(wallet.privkey)
    }

    await broadcast(tx, true)

    console.log(tx.hash)
}


async function walletSplit() {
    let splits = parseInt(process.argv[4])

    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    let balance = wallet.utxos.reduce((acc, curr) => acc + curr.satoshis, 0)
    if (balance == 0) throw new Error('no funds to split')

    let tx = new Transaction()
    tx.from(wallet.utxos)
    for (let i = 0; i < splits - 1; i++) {
        tx.to(wallet.address, Math.floor(balance / splits))
    }
    tx.change(wallet.address)
    tx.sign(wallet.privkey)

    await broadcast(tx, true)

    console.log(tx.hash)
}


const MAX_SCRIPT_ELEMENT_SIZE = 520

async function mint() {
    const argAddress = process.argv[3]
    const argContentTypeOrFilename = process.argv[4]
    const argHexData = process.argv[5]


    let address = new Address(argAddress)
    let contentType
    let data

    if (fs.existsSync(argContentTypeOrFilename)) {
        contentType = mime.contentType(mime.lookup(argContentTypeOrFilename))
        data = fs.readFileSync(argContentTypeOrFilename)
    } else {
        contentType = argContentTypeOrFilename
        if (!/^[a-fA-F0-9]*$/.test(argHexData)) throw new Error('data must be hex')
        data = Buffer.from(argHexData, 'hex')
    }

    if (data.length == 0) {
        throw new Error('no data to mint')
    }

    if (contentType.length > MAX_SCRIPT_ELEMENT_SIZE) {
        throw new Error('content type too long')
    }


    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH))

    let txs = inscribe(wallet, address, contentType, data)

    await broadcastAll(txs, false)
}

async function broadcastAll(txs, retry) {
    for (let i = 0; i < txs.length; i++) {
        console.log(`broadcasting tx ${i + 1} of ${txs.length}`)

        try {
            //throw new Error('hello')
            await broadcast(txs[i], retry)
        } catch (e) {
            console.log('broadcast failed', e)
            console.log('saving pending txs to pending-txs.json')
            console.log('to reattempt broadcast, re-run the command')
            fs.writeFileSync('pending-txs.json', JSON.stringify(txs.slice(i).map(tx => tx.toString())))
            process.exit(1)
        }
    }

    try{
        fs.unlinkSync('pending-txs.json')
    } catch (e){
        console.log('issue deleting file')
    }

    console.log('inscription txid:', txs[1].hash)
}


function bufferToChunk(b, type) {
    b = Buffer.from(b, type)
    return {
        buf: b.length ? b : undefined,
        len: b.length,
        opcodenum: b.length <= 75 ? b.length : b.length <= 255 ? 76 : 77
    }
}

function numberToChunk(n) {
    return {
        buf: n <= 16 ? undefined : n < 128 ? Buffer.from([n]) : Buffer.from([n % 256, n / 256]),
        len: n <= 16 ? 0 : n < 128 ? 1 : 2,
        opcodenum: n == 0 ? 0 : n <= 16 ? 80 + n : n < 128 ? 1 : 2
    }
}

function opcodeToChunk(op) {
    return { opcodenum: op }
}


const MAX_CHUNK_LEN = 240
const MAX_PAYLOAD_LEN = 1500


function inscribe(wallet, address, contentType, data) {
    let txs = []


    let privateKey = new PrivateKey(wallet.privkey)
    let publicKey = privateKey.toPublicKey()


    let parts = []
    while (data.length) {
        let part = data.slice(0, Math.min(MAX_CHUNK_LEN, data.length))
        data = data.slice(part.length)
        parts.push(part)
    }


    let inscription = new Script()
    inscription.chunks.push(bufferToChunk('ord'))
    inscription.chunks.push(numberToChunk(parts.length))
    inscription.chunks.push(bufferToChunk(contentType))
    parts.forEach((part, n) => {
        inscription.chunks.push(numberToChunk(parts.length - n - 1))
        inscription.chunks.push(bufferToChunk(part))
    })



    let p2shInput
    let lastLock
    let lastPartial

    while (inscription.chunks.length) {
        let partial = new Script()

        if (txs.length == 0) {
            partial.chunks.push(inscription.chunks.shift())
        }

        while (partial.toBuffer().length <= MAX_PAYLOAD_LEN && inscription.chunks.length) {
            partial.chunks.push(inscription.chunks.shift())
            partial.chunks.push(inscription.chunks.shift())
        }

        if (partial.toBuffer().length > MAX_PAYLOAD_LEN) {
            inscription.chunks.unshift(partial.chunks.pop())
            inscription.chunks.unshift(partial.chunks.pop())
        }


        let lock = new Script()
        lock.chunks.push(bufferToChunk(publicKey.toBuffer()))
        lock.chunks.push(opcodeToChunk(Opcode.OP_CHECKSIGVERIFY))
        partial.chunks.forEach(() => {
            lock.chunks.push(opcodeToChunk(Opcode.OP_DROP))
        })
        lock.chunks.push(opcodeToChunk(Opcode.OP_TRUE))



        let lockhash = Hash.ripemd160(Hash.sha256(lock.toBuffer()))


        let p2sh = new Script()
        p2sh.chunks.push(opcodeToChunk(Opcode.OP_HASH160))
        p2sh.chunks.push(bufferToChunk(lockhash))
        p2sh.chunks.push(opcodeToChunk(Opcode.OP_EQUAL))


        let p2shOutput = new Transaction.Output({
            script: p2sh,
            satoshis: 100000
        })


        let tx = new Transaction()
        if (p2shInput) tx.addInput(p2shInput)
        tx.addOutput(p2shOutput)
        console.log('FUCK THIS SHIT')
        fund(wallet, tx)

        if (p2shInput) {
            let signature = Transaction.sighash.sign(tx, privateKey, Signature.SIGHASH_ALL, 0, lastLock)
            let txsignature = Buffer.concat([signature.toBuffer(), Buffer.from([Signature.SIGHASH_ALL])])

            let unlock = new Script()
            unlock.chunks = unlock.chunks.concat(lastPartial.chunks)
            unlock.chunks.push(bufferToChunk(txsignature))
            unlock.chunks.push(bufferToChunk(lastLock.toBuffer()))
            tx.inputs[0].setScript(unlock)
        }


        updateWallet(wallet, tx)
        txs.push(tx)

        p2shInput = new Transaction.Input({
            prevTxId: tx.hash,
            outputIndex: 0,
            output: tx.outputs[0],
            script: ''
        })

        p2shInput.clearSignatures = () => {}
        p2shInput.getSignatures = () => {}


        lastLock = lock
        lastPartial = partial

    }


    let tx = new Transaction()
    tx.addInput(p2shInput)
    tx.to(address, 100000)

    console.log('tx: ',tx)

    fund(wallet, tx)

    let signature = Transaction.sighash.sign(tx, privateKey, Signature.SIGHASH_ALL, 0, lastLock)
    let txsignature = Buffer.concat([signature.toBuffer(), Buffer.from([Signature.SIGHASH_ALL])])

    let unlock = new Script()
    unlock.chunks = unlock.chunks.concat(lastPartial.chunks)
    unlock.chunks.push(bufferToChunk(txsignature))
    unlock.chunks.push(bufferToChunk(lastLock.toBuffer()))
    tx.inputs[0].setScript(unlock)

    updateWallet(wallet, tx)
    txs.push(tx)


    return txs
}


function fund(wallet, tx) {
    console.log('1 tx input:', tx.inputAmount)
    console.log('1 tx output:', tx.outputAmount)
    console.log('1 tx fee:', tx.getFee())
    tx.change(wallet.address)
    delete tx._fee

    for (const utxo of wallet.utxos) {
        if (tx.inputs.length && tx.outputs.length && tx.inputAmount >= tx.outputAmount + tx.getFee()) {
            break
        }

        delete tx._fee
        console.log('UTXO: ',utxo)
        tx.from(utxo)
        console.log(wallet.address)
        tx.change(wallet.address)
        tx.sign(wallet.privkey)
        console.log('TX: ',tx)
    }

    if (tx.inputAmount < tx.outputAmount + tx.getFee()) {
        console.log('tx input:', tx.inputAmount)
        console.log('tx output:', tx.outputAmount)
        console.log('tx fee:', tx.getFee())
        throw new Error('not enough funds')
    }
}


function updateWallet(wallet, tx) {
    wallet.utxos = wallet.utxos.filter(utxo => {
        for (const input of tx.inputs) {
            if (input.prevTxId.toString('hex') == utxo.txid && input.outputIndex == utxo.vout) {
                return false
            }
        }
        return true
    })

    tx.outputs
        .forEach((output, vout) => {
            if (output.script.toAddress().toString() == wallet.address) {
                wallet.utxos.push({
                    txid: tx.hash,
                    vout,
                    script: output.script.toHex(),
                    satoshis: output.satoshis
                })
            }
        })
}


async function broadcast(tx, retry) {
    const body = tx.toString();

    const options = {
        headers: {
            "accept": "*/*",
            "content-type": "text/plain",
        },
        method: "POST",
    };

    while (true) {
        try {
            await axios.post("https://bells.quark.blue/api/tx", body, options);
            break;
        } catch (e) {
            if (!retry) throw e;
            let msg = e.response && e.response.data && e.response.data.error && e.response.data.error.message;
            if (msg && msg.includes('too-long-mempool-chain')) {
                console.warn('retrying, too-long-mempool-chain');
                await new Promise(resolve => setTimeout(resolve, 1000));
            } else {
                throw e;
            }
        }
    }

    let wallet = JSON.parse(fs.readFileSync(WALLET_PATH));
    updateWallet(wallet, tx);
    fs.writeFileSync(WALLET_PATH, JSON.stringify(wallet, 0, 2));
}


function chunkToNumber(chunk) {
    if (chunk.opcodenum == 0) return 0
    if (chunk.opcodenum == 1) return chunk.buf[0]
    if (chunk.opcodenum == 2) return chunk.buf[1] * 255 + chunk.buf[0]
    if (chunk.opcodenum > 80 && chunk.opcodenum <= 96) return chunk.opcodenum - 80
    return undefined
}


async function extract(txid) {
    let resp = await axios.get(`https://bells.quark.blue/api/tx/${txid}`)
    let transaction = resp.data.transaction
    let script = Script.fromHex(transaction.inputs[0].scriptSig.hex)
    let chunks = script.chunks


    let prefix = chunks.shift().buf.toString('utf8')
    if (prefix != 'ord') {
        throw new Error('not a doginal')
    }

    let pieces = chunkToNumber(chunks.shift())

    let contentType = chunks.shift().buf.toString('utf8')


    let data = Buffer.alloc(0)
    let remaining = pieces

    while (remaining && chunks.length) {
        let n = chunkToNumber(chunks.shift())

        if (n !== remaining - 1) {
            txid = transaction.outputs[0].spent.hash
            resp = await axios.get(`https://bells.quark.blue/api/tx/${txid}`)
            transaction = resp.data.transaction
            script = Script.fromHex(transaction.inputs[0].scriptSig.hex)
            chunks = script.chunks
            continue
        }

        data = Buffer.concat([data, chunks.shift().buf])
        remaining -= 1
    }

    return {
        contentType,
        data
    }
}


function server() {
    const app = express()
    const port = process.env.SERVER_PORT ? parseInt(process.env.SERVER_PORT) : 3000

    app.get('/tx/:txid', (req, res) => {
        extract(req.params.txid).then(result => {
            res.setHeader('content-type', result.contentType)
            res.send(result.data)
        }).catch(e => res.send(e.message))
    })

    app.listen(port, () => {
        console.log(`Listening on port ${port}`)
        console.log()
        console.log(`Example:`)
        console.log(`http://localhost:${port}/tx/15f3b73df7e5c072becb1d84191843ba080734805addfccb650929719080f62e`)
    })
}


main().catch(e => {
    let reason = e.response && e.response.data && e.response.data.error && e.response.data.error.message
    console.error(reason ? e.message + ':' + reason : e.message)
})
