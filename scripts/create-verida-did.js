import { DIDClient } from '@verida/did-client';

const veridaDidClient = new DIDClient({
    network: process.env.NODE_ENV === 'development' ? 'local' : 'banksia',
    rpcUrl: process.env.VDA_RPC_URL || 'https://rpc.verida.net',
});

console.log(veridaDidClient);