import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.ts';
import { v5 as uuidv5 } from 'uuid';
import fs from 'fs';

dotenv.config();


(async () => {
    const { agent, did } = await packageStore.initialize();
    const credentialId = uuidv5("https://www.linkedin.com/in/lukenispel/" + new Date().toISOString(), uuidv5.URL); // Generate a UUID from the did
    const credential = {
        '@context': ['https://www.w3.org/2018/endorsements/v1'],
        id: credentialId, // Ensure this is a URI
        type: ['VerifiableCredential', 'VerifiableEndorsement'],
        issuer: { id: did,
            nameOfIssuer: 'Luke Nispel',
            alsoKnownAs: 'Luke Nispel',
            website: 'https://www.linkedin.com/in/lukenispel/',
            socialMediaPlatforms: [{
                socialMediaHandle: 'lukenispel',
                socialMediaPlatformName: 'LinkedIn',
                socialMediaPlatformWebsite: 'https://www.linkedin.com/in/lukenispel/',
            }],
            avatar: 'https://lh3.googleusercontent.com/a/ACg8ocL_XUSEgkS8xPNZL_6ycFGSwQtIWKJ80ypNlE22GcucLmDmGA=s96-c',
         },
        issuanceDate: new Date().toISOString(), // Add issuanceDate
        issued: new Date().toISOString(), // Add issued
        validFrom: new Date().toISOString(),
        credentialSubject: { // Update from credentialSubject
            id: 'lindsay@withyouproductions.com',
            nameOfEndorsee: 'Lindsay Ladd',
            alsoKnownAs: 'Lindsay On Tech',
            website: 'https://www.linkedin.com/in/lindsayontech/',
            endorsedFor: [{
                socialMediaHandle: 'Lindsay On Tech',
                socialMediaPlatformName: 'LinkedIn',
                socialMediaPlatformWebsite: 'https://www.linkedin.com/in/lindsayontech/',
                superpower: 'Taking complex problems in high-stress situations and making them actionable, forward-thinking plans while staying focused on the mission with clear discernment.',
                strengths: ['Goal-Focused Project Management', 'Strategic Thinking', 'Critical Decision-making', 'Creative', 'Curious', 'Dedicated', 'Determined', 'Empathetic', 'Enthusiastic', 'Flexible', 'Innovative', 'Natural Leader', 'Problem-solving', 'Resilient', 'Cohesive Team Player', 'Excellent Time Management', 'Strong Work Ethic'],
            }],
            
        },
    };

    const signedCreation = await agent.createVerifiableCredential({
        credential,
        proofFormat: 'jwt'
    });

    // Save the signed credential to a file
    fs.writeFileSync('signed-credential.json', JSON.stringify(signedCreation, null, 2));
    console.log('Signed credential saved to signed-credential.json');
})();