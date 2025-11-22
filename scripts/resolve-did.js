import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.ts';

dotenv.config();

(async () => {
    const { agent } = await packageStore.initialize();
    const did = await agent.resolveDid({
        didUrl: 'did:ont:AN5g6gz9EoQ3sCNu7514GEghZurrktCMiH',
    });
    console.log(did);
})();