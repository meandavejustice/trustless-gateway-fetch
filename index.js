import { CID } from 'multiformats/cid';
import { identity } from 'multiformats/hashes/identity';
import { sha256, sha512 } from 'multiformats/hashes/sha2';
import { equals as uint8ArrayEquals } from 'uint8arrays/equals';
import { trustlessGateway } from 'helia/block-brokers';
class CodeError extends Error {
    code;
    props;
    constructor(message, code, props) {
        super(message);
        this.code = code;
        this.name = props?.name ?? 'CodeError';
        this.props = props ?? {}; // eslint-disable-line @typescript-eslint/consistent-type-assertions
    }
}
export const getCidBlockVerifierFunction = (cid, hashers) => {
    const hasher = hashers.find(hasher => hasher.code === cid.multihash.code);
    if (hasher == null) {
        throw new CodeError(`No hasher configured for multihash code 0x${cid.multihash.code.toString(16)}, please configure one. You can look up which hash this is at https://github.com/multiformats/multicodec/blob/master/table.csv`, 'ERR_UNKNOWN_HASH_ALG');
    }
    return async (block) => {
        // verify block
        const hash = await hasher.digest(block);
        if (!uint8ArrayEquals(hash.digest, cid.multihash.digest)) {
            // if a hash mismatch occurs for a TrustlessGatewayBlockBroker, we should try another gateway
            throw new CodeError('Hash of downloaded block did not match multihash from passed CID', 'ERR_HASH_MISMATCH');
        }
    };
};
export default async function trustlessGatewayFetch(cid, gateways, hashers) {
    if (typeof cid === 'string') {
        try {
            cid = CID.parse(cid);
        }
        catch (error) {
            console.error('Improperly formatted CID', error);
            return;
        }
    }
    const gatewayBlockBroker = trustlessGateway();
    const validateFn = getCidBlockVerifierFunction(cid, [
        sha256,
        sha512,
        identity
    ]);
    const block = await gatewayBlockBroker().retrieve(cid, { validateFn });
    return block;
}
