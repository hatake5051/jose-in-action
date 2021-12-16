export { AGCMEnc, isAGCMEnc };

/**
 * jwa#5.3.  Content Encryption with AES GCM
 */
type AGCMEnc = typeof agcmEncList[number];
const isAGCMEnc = (arg: unknown): arg is AGCMEnc => agcmEncList.some((a) => a === arg);
const agcmEncList = ['A128GCM', 'A192GCM', 'A256GCM'] as const;
