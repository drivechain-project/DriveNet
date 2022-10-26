// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <chain.h>
#include <clientversion.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <httpserver.h>
#include <init.h>
#include <merkleblock.h>
#include <net.h>
#include <netbase.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <sidechain.h>
#include <sidechaindb.h>
#include <timedata.h>
#include <txdb.h>
#include <util.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <validation.h>
#ifdef ENABLE_WALLET
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#endif
#include <warnings.h>

#include <stdint.h>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

#include <univalue.h>

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    CWallet * const pwallet;

    explicit DescribeAddressVisitor(CWallet *_pwallet) : pwallet(_pwallet) {}

    void ProcessSubScript(const CScript& subscript, UniValue& obj, bool include_addresses = false) const
    {
        // Always present: script type and redeemscript
        txnouttype which_type;
        std::vector<std::vector<unsigned char>> solutions_data;
        Solver(subscript, which_type, solutions_data);
        obj.pushKV("script", GetTxnOutputType(which_type));
        obj.pushKV("hex", HexStr(subscript.begin(), subscript.end()));

        CTxDestination embedded;
        UniValue a(UniValue::VARR);
        if (ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            UniValue subobj = boost::apply_visitor(*this, embedded);
            subobj.pushKV("address", EncodeDestination(embedded));
            subobj.pushKV("scriptPubKey", HexStr(subscript.begin(), subscript.end()));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.pushKV("pubkey", subobj["pubkey"]);
            obj.pushKV("embedded", std::move(subobj));
            if (include_addresses) a.push_back(EncodeDestination(embedded));
        } else if (which_type == TX_MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            // TODO: abstract out the common functionality between this logic and ExtractDestinations.
            obj.pushKV("sigsrequired", solutions_data[0][0]);
            UniValue pubkeys(UniValue::VARR);
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                if (include_addresses) a.push_back(EncodeDestination(key.GetID()));
                pubkeys.push_back(HexStr(key.begin(), key.end()));
            }
            obj.pushKV("pubkeys", std::move(pubkeys));
        }

        // The "addresses" field is confusing because it refers to public keys using their P2PKH address.
        // For that reason, only add the 'addresses' field when needed for backward compatibility. New applications
        // can use the 'embedded'->'address' field for P2SH or P2WSH wrapped addresses, and 'pubkeys' for
        // inspecting multisig participants.
        if (include_addresses) obj.pushKV("addresses", std::move(a));
    }

    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("iswitness", false));
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        obj.push_back(Pair("iswitness", false));
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            ProcessSubScript(subscript, obj, true);
        }
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pubkey;
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("iswitness", true));
        obj.push_back(Pair("witness_version", 0));
        obj.push_back(Pair("witness_program", HexStr(id.begin(), id.end())));
        if (pwallet && pwallet->GetPubKey(CKeyID(id), pubkey)) {
            obj.push_back(Pair("pubkey", HexStr(pubkey)));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        obj.push_back(Pair("iswitness", true));
        obj.push_back(Pair("witness_version", 0));
        obj.push_back(Pair("witness_program", HexStr(id.begin(), id.end())));
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (pwallet && pwallet->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("iswitness", true));
        obj.push_back(Pair("witness_version", (int)id.version));
        obj.push_back(Pair("witness_program", HexStr(id.program, id.program + id.length)));
        return obj;
    }
};
#endif

UniValue validateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "validateaddress \"address\"\n"
            "\nReturn information about the given bitcoin address.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) The bitcoin address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"address\",        (string) The bitcoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is watchonly\n"
            "  \"isscript\" : true|false,      (boolean, optional) If the address is P2SH or P2WSH. Not included for unknown witness types.\n"
            "  \"iswitness\" : true|false,     (boolean) If the address is P2WPKH, P2WSH, or an unknown witness version\n"
            "  \"witness_version\" : version   (number, optional) For all witness output types, gives the version number.\n"
            "  \"witness_program\" : \"hex\"     (string, optional) For all witness output types, gives the script or key hash present in the address.\n"
            "  \"script\" : \"type\"             (string, optional) The output script type. Only if \"isscript\" is true and the redeemscript is known. Possible types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash, witness_v0_scripthash, witness_unknown\n"
            "  \"hex\" : \"hex\",                (string, optional) The redeemscript for the P2SH or P2WSH address\n"
            "  \"addresses\"                   (string, optional) Array of addresses associated with the known redeemscript (only if \"iswitness\" is false). This field is superseded by the \"pubkeys\" field and the address inside \"embedded\".\n"
            "    [\n"
            "      \"address\"\n"
            "      ,...\n"
            "    ]\n"
            "  \"pubkeys\"                     (string, optional) Array of pubkeys associated with the known redeemscript (only if \"script\" is \"multisig\")\n"
            "    [\n"
            "      \"pubkey\"\n"
            "      ,...\n"
            "    ]\n"
            "  \"sigsrequired\" : xxxxx        (numeric, optional) Number of signatures required to spend multisig output (only if \"script\" is \"multisig\")\n"
            "  \"pubkey\" : \"publickeyhex\",    (string, optional) The hex value of the raw public key, for single-key addresses (possibly embedded in P2SH or P2WSH)\n"
            "  \"embedded\" : {...},           (object, optional) information about the address embedded in P2SH or P2WSH, if relevant and known. It includes all validateaddress output fields for the embedded address, excluding \"isvalid\", metadata (\"timestamp\", \"hdkeypath\", \"hdmasterkeyid\") and relation to the wallet (\"ismine\", \"iswatchonly\", \"account\").\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is the default account\n"
            "  \"timestamp\" : timestamp,      (number, optional) The creation time of the key if available in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD keypath if the key is HD and available\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (string, optional) The Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
        );

#ifdef ENABLE_WALLET
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

#ifdef ENABLE_WALLET
        isminetype mine = pwallet ? IsMine(*pwallet, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", bool(mine & ISMINE_SPENDABLE)));
        ret.push_back(Pair("iswatchonly", bool(mine & ISMINE_WATCH_ONLY)));
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(pwallet), dest);
        ret.pushKVs(detail);
        if (pwallet && pwallet->mapAddressBook.count(dest)) {
            ret.push_back(Pair("account", pwallet->mapAddressBook[dest].name));
        }
        if (pwallet) {
            const CKeyMetadata* meta = nullptr;
            CKeyID key_id = GetKeyForDestination(*pwallet, dest);
            if (!key_id.IsNull()) {
                auto it = pwallet->mapKeyMetadata.find(key_id);
                if (it != pwallet->mapKeyMetadata.end()) {
                    meta = &it->second;
                }
            }
            if (!meta) {
                auto it = pwallet->m_script_metadata.find(CScriptID(scriptPubKey));
                if (it != pwallet->m_script_metadata.end()) {
                    meta = &it->second;
                }
            }
            if (meta) {
                ret.push_back(Pair("timestamp", meta->nCreateTime));
                if (!meta->hdKeypath.empty()) {
                    ret.push_back(Pair("hdkeypath", meta->hdKeypath));
                    ret.push_back(Pair("hdmasterkeyid", meta->hdMasterKeyID.GetHex()));
                }
            }
        }
#endif
    }
    return ret;
}

// Needed even with !ENABLE_WALLET, to pass (ignored) pointers around
class CWallet;

UniValue createmultisig(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 2)
    {
        std::string msg = "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"
            "\nArguments:\n"
            "1. nrequired                    (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"                       (string, required) A json array of hex-encoded public keys\n"
            "     [\n"
            "       \"key\"                    (string) The hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 public keys\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys.size(); ++i) {
        if (IsHex(keys[i].get_str()) && (keys[i].get_str().length() == 66 || keys[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys[i].get_str()));
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid public key: %s\nNote that from v0.16, createmultisig no longer accepts addresses."
            " Users must use addmultisigaddress to create multisig addresses with addresses known to the wallet.", keys[i].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner = CreateMultisigRedeemscript(required, pubkeys);
    CScriptID innerID(inner);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", EncodeDestination(innerID)));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}

UniValue verifymessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifymessage \"address\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The bitcoin address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = boost::get<CKeyID>(&destination);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == *keyID);
}

UniValue signmessagewithprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "signmessagewithprivkey \"privkey\" \"message\"\n"
            "\nSign a message with the private key of an address\n"
            "\nArguments:\n"
            "1. \"privkey\"         (string, required) The private key to sign the message with.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
        );

    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strPrivkey);
    if (!fGood)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    CKey key = vchSecret.GetKey();
    if (!key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

UniValue setmocktime(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw std::runtime_error("setmocktime for regression testing (-regtest mode) only");

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    SetMockTime(request.params[0].get_int64());

    return NullUniValue;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("used", uint64_t(stats.used)));
    obj.push_back(Pair("free", uint64_t(stats.free)));
    obj.push_back(Pair("total", uint64_t(stats.total)));
    obj.push_back(Pair("locked", uint64_t(stats.locked)));
    obj.push_back(Pair("chunks_used", uint64_t(stats.chunks_used)));
    obj.push_back(Pair("chunks_free", uint64_t(stats.chunks_free)));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getmemoryinfo (\"mode\")\n"
            "Returns an object containing information about memory usage.\n"
            "Arguments:\n"
            "1. \"mode\" determines what kind of information is returned. This argument is optional, the default mode is \"stats\".\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc 2.10+).\n"
            "\nResult (mode \"stats\"):\n"
            "{\n"
            "  \"locked\": {               (json object) Information about locked memory manager\n"
            "    \"used\": xxxxx,          (numeric) Number of bytes used\n"
            "    \"free\": xxxxx,          (numeric) Number of bytes available in current arenas\n"
            "    \"total\": xxxxxxx,       (numeric) Total number of bytes managed\n"
            "    \"locked\": xxxxxx,       (numeric) Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk.\n"
            "    \"chunks_used\": xxxxx,   (numeric) Number allocated chunks\n"
            "    \"chunks_free\": xxxxx,   (numeric) Number unused chunks\n"
            "  }\n"
            "}\n"
            "\nResult (mode \"mallocinfo\"):\n"
            "\"<malloc version=\"1\">...\"\n"
            "\nExamples:\n"
            + HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
        );

    std::string mode = request.params[0].isNull() ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("locked", RPCLockedMemoryInfo()));
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo is only available when compiled with glibc 2.10+");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
}

uint32_t getCategoryMask(UniValue cats) {
    cats = cats.get_array();
    uint32_t mask = 0;
    for (unsigned int i = 0; i < cats.size(); ++i) {
        uint32_t flag = 0;
        std::string cat = cats[i].get_str();
        if (!GetLogCategory(&flag, &cat)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
        if (flag == BCLog::NONE) {
            return 0;
        }
        mask |= flag;
    }
    return mask;
}

UniValue logging(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "logging ( <include> <exclude> )\n"
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories with status that are currently being debug logged or not.\n"
            "When called with arguments, adds or removes categories from debug logging and return the lists above.\n"
            "The arguments are evaluated in order \"include\", \"exclude\".\n"
            "If an item is both included and excluded, it will thus end up being excluded.\n"
            "The valid logging categories are: " + ListLogCategories() + "\n"
            "In addition, the following are available as category names with special meanings:\n"
            "  - \"all\",  \"1\" : represent all logging categories.\n"
            "  - \"none\", \"0\" : even if other logging categories are specified, ignore all of them.\n"
            "\nArguments:\n"
            "1. \"include\"        (array of strings, optional) A json array of categories to add debug logging\n"
            "     [\n"
            "       \"category\"   (string) the valid logging category\n"
            "       ,...\n"
            "     ]\n"
            "2. \"exclude\"        (array of strings, optional) A json array of categories to remove debug logging\n"
            "     [\n"
            "       \"category\"   (string) the valid logging category\n"
            "       ,...\n"
            "     ]\n"
            "\nResult:\n"
            "{                   (json object where keys are the logging categories, and values indicates its status\n"
            "  \"category\": 0|1,  (numeric) if being debug logged or not. 0:inactive, 1:active\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], \"[libevent]\"")
        );
    }

    uint32_t originalLogCategories = logCategories;
    if (request.params[0].isArray()) {
        logCategories |= getCategoryMask(request.params[0]);
    }

    if (request.params[1].isArray()) {
        logCategories &= ~getCategoryMask(request.params[1]);
    }

    // Update libevent logging if BCLog::LIBEVENT has changed.
    // If the library version doesn't allow it, UpdateHTTPServerLogging() returns false,
    // in which case we should clear the BCLog::LIBEVENT flag.
    // Throw an error if the user has explicitly asked to change only the libevent
    // flag and it failed.
    uint32_t changedLogCategories = originalLogCategories ^ logCategories;
    if (changedLogCategories & BCLog::LIBEVENT) {
        if (!UpdateHTTPServerLogging(logCategories & BCLog::LIBEVENT)) {
            logCategories &= ~BCLog::LIBEVENT;
            if (changedLogCategories == BCLog::LIBEVENT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "libevent logging cannot be updated when using libevent before v2.1.1.");
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    std::vector<CLogCategoryActive> vLogCatActive = ListActiveLogCategories();
    for (const auto& logCatActive : vLogCatActive) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
}

UniValue createcriticaldatatx(const JSONRPCRequest& request)
{
    // TODO finish
    //
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "createcriticaldatatx\n"
            "Create a critical data transaction\n"
            "\nArguments:\n"
            "1. \"amount\"         (numeric or string, required) The amount in " + CURRENCY_UNIT + " to be spent.\n"
            "2. \"height\"         (numeric, required) The block height this transaction must be included in.\n"
            "3. \"criticalhash\"   (string, required) h* you want added to a coinbase\n"
            "\nExamples:\n"
            + HelpExampleCli("createcriticaldatatx", "\"amount\", \"height\", \"criticalhash\"")
            + HelpExampleRpc("createcriticaldatatx", "\"amount\", \"height\", \"criticalhash\"")
            );

    // TODO remove after finished
    throw JSONRPCError(RPC_INTERNAL_ERROR, "Sorry, this function is not supported yet.");

    // Amount
    CAmount nAmount = AmountFromValue(request.params[0]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    int nHeight = request.params[1].get_int();

    // Critical hash
    uint256 hashCritical = uint256S(request.params[2].get_str());
    if (hashCritical.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid h*");

#ifdef ENABLE_WALLET
    // Create and send the transaction
    std::string strError;
    if (vpwallets.empty()){
        strError = "Error: no wallets are available";
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    std::vector<CRecipient> vecSend;
    CRecipient recipient = {CScript() << OP_0, nAmount, false};
    vecSend.push_back(recipient);

    LOCK2(cs_main, vpwallets[0]->cs_wallet);

    CWalletTx wtx;
    CReserveKey reservekey(vpwallets[0]);
    CAmount nFeeRequired;
    int nChangePosRet = -1;
    //TODO: set this as a real thing
    CCoinControl cc;
    if (!vpwallets[0]->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, cc)) {
        if (nAmount + nFeeRequired > vpwallets[0]->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!vpwallets[0]->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
#endif

    UniValue ret(UniValue::VOBJ);
#ifdef ENABLE_WALLET
    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));
    ret.push_back(Pair("nChangePos", nChangePosRet));
#endif

    return ret;
}

UniValue listsidechainctip(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "listsidechainctip\n"
            "Returns the crtitical transaction index pair for nSidechain\n"
            "\nArguments:\n"
            "1. \"nsidechain\"      (numeric, required) The sidechain number\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechainctip", "\"nsidechain\"")
            + HelpExampleRpc("listsidechainctip", "\"nsidechain\"")
            );

    // Is nSidechain valid?
    int nSidechain = request.params[0].get_int();
    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    SidechainCTIP ctip;
    if (!scdb.GetCTIP(nSidechain, ctip))
        throw JSONRPCError(RPC_MISC_ERROR, "No CTIP found for sidechain!");

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("txid", ctip.out.hash.ToString()));
    obj.push_back(Pair("n", (int64_t)ctip.out.n));
    obj.push_back(Pair("amount", ctip.amount));
    obj.push_back(Pair("amountformatted", FormatMoney(ctip.amount)));

    return obj;
}

UniValue listsidechaindeposits(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "listsidechaindeposits\n"
            "List the most recent cached deposits for sidechain.\n"
            "Optionally limited to count. Note that this only has access to "
            "deposits which are currently cached.\n"
            "\nArguments:\n"
            "1. \"nsidechain\"  (numeric, required) The sidechain number\n"
            "2. \"txid\"        (string, optional) Only return deposits after this deposit TXID\n"
            "3. \"n\"           (numeric, optional, required if txid is set) The output index of the previous argument txn\n"
            "4. \"count\"       (numeric, optional) The number of most recent deposits to list\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechaindeposits", "\"sidechainkey\", \"count\"")
            + HelpExampleRpc("listsidechaindeposits", "\"sidechainkey\", \"count\"")
            );

#ifdef ENABLE_WALLET
    // Check for active wallet
    std::string strError;
    if (vpwallets.empty()) {
        strError = "Error: no wallets are available";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
#endif

    // Check sidechain number
    int nSidechain = request.params[0].get_int();
    if (nSidechain < 0 || nSidechain > 255)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    // If TXID was passed in, make sure we also received N
    if (request.params.size() > 1 && request.params.size() < 3) {
        std::string strError = "Output index 'n' is required if TXID is provided!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Was a TXID passed in?
    uint256 txidKnown;
    if (request.params.size() > 1) {
        std::string strTXID = request.params[1].get_str();
        txidKnown = uint256S(strTXID);
        if (txidKnown.IsNull()) {
            std::string strError = "Invalid TXID!";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }
    }

    // Was N passed in?
    uint32_t nKnown = 0;
    if (request.params.size() > 2) {
        nKnown = request.params[2].get_int();
    }

    // Get number of recent deposits to return (default is all cached deposits)
    bool fLimit = false;
    int count = 0;
    if (request.params.size() == 4) {
        fLimit = true;
        count = request.params[3].get_int();
    }

    UniValue arr(UniValue::VARR);

#ifdef ENABLE_WALLET
    std::vector<SidechainDeposit> vDeposit = scdb.GetDeposits(nSidechain);
    if (!vDeposit.size()) {
        std::string strError = "No deposits in cache for this sidechain!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    for (auto rit = vDeposit.crbegin(); rit != vDeposit.crend(); rit++) {
        const SidechainDeposit d = *rit;

        // Check if we have reached a deposit the sidechain already has. The
        // sidechain can pass in a TXID & output index 'n' to let us know what
        // the latest deposit they've already received is.
        if (!txidKnown.IsNull() && d.tx.GetHash() == txidKnown && d.nBurnIndex == nKnown)
        {
            LogPrintf("%s: Reached known deposit. TXID: %s n: %u\n",
                    __func__, txidKnown.ToString(), nKnown);
            break;
        }

        // Add deposit txid to set
        uint256 txid = d.tx.GetHash();
        std::set<uint256> setTxids;
        setTxids.insert(txid);

        LOCK(cs_main);

        BlockMap::iterator it = mapBlockIndex.find(d.hashBlock);
        if (it == mapBlockIndex.end()) {
            std::string strError = "Block hash not found";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
        }

        CBlockIndex* pblockindex = it->second;
        if (pblockindex == NULL) {
            std::string strError = "Block index null";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
        }

        if (!chainActive.Contains(pblockindex)) {
            std::string strError = "Block not in active chain";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
        }
#endif

#ifdef ENABLE_WALLET
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("nsidechain", d.nSidechain));
        obj.push_back(Pair("strdest", d.strDest));
        obj.push_back(Pair("txhex", EncodeHexTx(d.tx)));
        obj.push_back(Pair("nburnindex", (int)d.nBurnIndex));
        obj.push_back(Pair("ntx", (int)d.nTx));
        obj.push_back(Pair("hashblock", d.hashBlock.ToString()));

        arr.push_back(obj);
#endif
        if (fLimit) {
            count--;
            if (count <= 0)
                break;
        }
    }

    return arr;
}

UniValue countsidechaindeposits(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "countsidechaindeposits\n"
            "Returns the number of deposits (for nSidechain) currently cached. "
            "Note that this doesn't count all sidechain deposits, just the "
            "number currently cached by the node.\n"
            "\nArguments:\n"
            "1. \"nsidechain\"      (numeric, required) The sidechain number\n"
            "\nExamples:\n"
            + HelpExampleCli("countsidechaindeposits", "\"nsidechain\"")
            + HelpExampleRpc("countsidechaindeposits", "\"nsidechain\"")
            );

#ifdef ENABLE_WALLET
    // Check for active wallet
    std::string strError;
    if (vpwallets.empty()) {
        strError = "Error: no wallets are available";
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
#endif

    // Is nSidechain valid?
    int nSidechain = request.params[0].get_int();
    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number");

    int count = 0;

    // Get latest deposit from sidechain DB deposit cache
    std::vector<SidechainDeposit> vDeposit = scdb.GetDeposits(nSidechain);
    count = vDeposit.size();

    return count;
}

UniValue addwithdrawal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "addwithdrawal\n"
            "For testing purposes only! Add withdrawal to SCDB\n"
            "\nArguments:\n"
            "1. \"nsidechain\"      (int, required) Sidechain number\n"
            "2. \"hash\"            (string, required) Bundle hash\n"
            "\nExamples:\n"
            + HelpExampleCli("addwithdrawal", "")
            + HelpExampleRpc("addwithdrawal", "")
    );

    // Is nSidechain valid?
    int nSidechain = request.params[0].get_int();
    if (!scdb.IsSidechainActive(nSidechain)) {
        std::string strError = "Invalid sidechain number!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    uint256 hash = uint256S(request.params[1].get_str());
    if (hash.IsNull()) {
        std::string strError = "Invalid bundle hash!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    if (!scdb.AddWithdrawal(nSidechain, hash, true /* fDebug */)) {
        std::string strError = "Failed to add withdrawal!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    return NullUniValue;
}

UniValue receivewithdrawalbundle(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "receivewithdrawalbundle\n"
            "Called by sidechain to announce new withdrawal for verification\n"
            "\nArguments:\n"
            "1. \"nsidechain\"      (int, required) The sidechain number\n"
            "2. \"rawtx\"           (string, required) The raw transaction hex\n"
            "\nExamples:\n"
            + HelpExampleCli("receivewithdrawalbundle", "")
            + HelpExampleRpc("receivewithdrawalbundle", "")
     );

#ifndef ENABLE_WALLET
    strError = "Error: Wallet disabled";
    LogPrintf("%s: %s\n", __func__, strError);
    throw JSONRPCError(RPC_WALLET_ERROR, strError);
#endif

#ifdef ENABLE_WALLET
    // Check for active wallet
    std::string strError;
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        strError = "Error: no wallets are available";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
#endif

    // Is nSidechain valid?
    int nSidechain = request.params[0].get_int();
    if (!scdb.IsSidechainActive(nSidechain)) {
        strError = "Invalid sidechain number!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Create CTransaction from hex
    CMutableTransaction mtx;
    std::string hex = request.params[1].get_str();
    if (!DecodeHexTx(mtx, hex)) {
        strError = "Invalid transaction hex!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    CTransaction withdrawal(mtx);

    if (withdrawal.IsNull()) {
        strError = "Invalid withdrawal hex";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Reject the withdrawal if it spends more than the sidechain's CTIP as it won't
    // be accepted anyway
    CAmount amount = withdrawal.GetValueOut();
    std::vector<COutput> vSidechainCoin;
    CScript scriptPubKey;
    if (!scdb.GetSidechainScript(nSidechain, scriptPubKey)) {
        strError = "Cannot get script for sidechain!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    SidechainCTIP ctip;
    if (!scdb.GetCTIP(nSidechain, ctip)) {
        strError = "Rejecting withdrawal: No CTIP found!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    if (amount > ctip.amount) {
        strError = "Rejecting withdrawal: Withdrawn amount greater than CTIP amount!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Check for the required withdrawal change return destination OP_RETURN output
    for (size_t i = 0; i < mtx.vout.size(); i++) {
        const CScript& scriptPubKey = mtx.vout[i].scriptPubKey;
        if (!scriptPubKey.size())
            continue;
        if (scriptPubKey.front() != OP_RETURN)
            continue;

        if (scriptPubKey.size() < 3) {
            strError = "Rejecting Withdrawal: First OP_RETURN output invalid size (too small)!\n";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }

        CScript::const_iterator pDest = scriptPubKey.begin() + 1;
        opcodetype opcode;
        std::vector<unsigned char> vch;
        if (!scriptPubKey.GetOp(pDest, opcode, vch) || vch.empty()) {
            strError = "Rejecting Withdrawal: First OP_RETURN output invalid. (Failed GetOp)!\n";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }
        std::string strDest((const char*)vch.data(), vch.size());
        if (strDest != SIDECHAIN_WITHDRAWAL_RETURN_DEST) {
            strError = "Rejecting Withdrawal: First OP_RETURN output invalid. (incorrect dest)!\n";
            LogPrintf("%s: %s\n", __func__, strError);
            throw JSONRPCError(RPC_MISC_ERROR, strError);
        }
        break;
    }

    // Add Withdrawal to our local cache so that we can create a Withdrawal hash commitment
    // in the next block we mine to begin the verification process
    if (!scdb.CacheWithdrawalTx(withdrawal, nSidechain)) {
        strError = "Withdrawal rejected from cache (duplicate?)";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    // Return Withdrawal hash to verify it has been received
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("wtxid", withdrawal.GetHash().GetHex()));
    return ret;
}

UniValue verifybmm(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifybmm\n"
            "Check if a mainchain block includes BMM for a sidechain h*\n"
            "\nArguments:\n"
            "1. \"blockhash\"      (string, required) mainchain blockhash with h*\n"
            "2. \"bmmhash\"        (string, required) h* to locate\n"
            "3. \"nsidechain\"     (number, required) sidechain number\n"
            "\nExamples:\n"
            + HelpExampleCli("verifybmm", "\"blockhash\", \"bmmhash\", \"nsidechain\"")
            + HelpExampleRpc("verifybmm", "\"blockhash\", \"bmmhash\", \"nsidechain\"")
            );

    uint256 hashBlock = uint256S(request.params[0].get_str());
    uint256 hashBMM = uint256S(request.params[1].get_str());
    int nSidechain = request.params[2].get_int();

    // Is nSidechain valid?
    if (!scdb.IsSidechainActive(nSidechain)) {
        std::string strError = "Invalid sidechain number!";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    if (!mapBlockIndex.count(hashBlock)) {
        std::string strError = "Block not found";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    CBlockIndex* pblockindex = mapBlockIndex[hashBlock];
    if (pblockindex == NULL)
    {
        std::string strError = "pblockindex null";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
    {
        std::string strError = "Failed to read block from disk";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    if (!block.vtx.size()) {
        std::string strError = "No txns in block";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    bool fBMMFound = false;
    const CTransaction &txCoinbase = *(block.vtx[0]);
    for (const CTxOut& out : txCoinbase.vout) {
        const CScript& scriptPubKey = out.scriptPubKey;

        uint256 hashCritical = uint256();
        std::vector<unsigned char> vBytes;
        if (!scriptPubKey.IsCriticalHashCommit(hashCritical, vBytes))
            continue;

        // Create critical data object and validate BMM
        CCriticalData data;
        data.hashCritical = hashCritical;
        data.vBytes = vBytes;

        uint8_t nSidechainBMM;
        std::string strPrevBlock = "";
        if (!data.IsBMMRequest(nSidechainBMM, strPrevBlock))
            continue;

        // Check sidechain number
        if (nSidechain != nSidechainBMM)
            continue;

        // Check prev block bytes
        if (strPrevBlock != block.hashPrevBlock.ToString().substr(56, 63))
            continue;

        // Check h*
        if (hashBMM == data.hashCritical)
            fBMMFound = true;
    }

    if (!fBMMFound) {
        std::string strError = "h* not found in block";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    }

    UniValue ret(UniValue::VOBJ);
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("txid", txCoinbase.GetHash().ToString()));
    obj.push_back(Pair("time", itostr(block.nTime)));
    ret.push_back(Pair("bmm", obj));

    return ret;
}

UniValue verifydeposit(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifydeposit\n"
            "Check if a mainchain block includes valid deposit with txid.\n"
            "\nArguments:\n"
            "1. \"blockhash\"      (string, required) mainchain blockhash with deposit\n"
            "2. \"txid\"           (string, required) deposit txid to locate\n"
            "3. \"nTx\"            (int, required) deposit tx number in block\n"
            "\nExamples:\n"
            + HelpExampleCli("verifybmm", "\"blockhash\", \"txid\"")
            + HelpExampleRpc("verifybmm", "\"blockhash\", \"txid\"")
            );

    uint256 hashBlock = uint256S(request.params[0].get_str());
    uint256 txid = uint256S(request.params[1].get_str());
    int nTx = request.params[2].get_int();

    if (!mapBlockIndex.count(hashBlock)) {
        std::string strError = "Block not found";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    CBlockIndex* pblockindex = mapBlockIndex[hashBlock];
    if (pblockindex == NULL)
    {
        std::string strError = "pblockindex null";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    if (!scdb.HaveDepositCached(txid)) {
        std::string strError = "SCDB does not know deposit";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
    {
        std::string strError = "Failed to read block from disk";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    if (!block.vtx.size()) {
        std::string strError = "No txns in block";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    if ((int)block.vtx.size() <= nTx) {
        std::string strError = "nTx out of range for block";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    const CTransaction &tx = *(block.vtx[nTx]);
    if (tx.GetHash() != txid) {
        std::string strError = "Transaction at block index specified does not match txid";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    SidechainDeposit deposit;
    if (!scdb.TxnToDeposit(tx, nTx, hashBlock, deposit)) {
        std::string strError = "Invalid deposit transaction format";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    return tx.GetHash().ToString();
}

UniValue listpreviousblockhashes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listpreviousblockhashes\n"
            "List the 5 most recent mainchain block hashes. Used by sidechains " \
            "to help search for BMM commitments.\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listpreviousblockhashes", "")
            + HelpExampleRpc("listpreviousblockhashes", "")
            );

    int nHeight = chainActive.Height();
    int nStart = nHeight - 4;
    if (!(nHeight > 0) || !(nStart > 0))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Insufficient blocks connected to complete request!");

    std::vector<uint256> vHash;
    for (int i = nStart; i <= nHeight; i++) {
        uint256 hashBlock = chainActive[i]->GetBlockHash();
        vHash.push_back(hashBlock);
    }

    UniValue ret(UniValue::VARR);
    for (const uint256& hash : vHash) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("hash", hash.ToString()));
        ret.push_back(obj);
    }

    return ret;
}

UniValue listactivesidechains(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listactivesidechains\n"
            "List active sidechains.\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listactivesidechains", "")
            + HelpExampleRpc("listactivesidechains", "")
            );

    std::vector<Sidechain> vActive = scdb.GetActiveSidechains();
    UniValue ret(UniValue::VARR);
    for (const Sidechain& s : vActive) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", s.title));
        obj.push_back(Pair("description", s.description));
        obj.push_back(Pair("nversion", s.nVersion));
        obj.push_back(Pair("hashid1", s.hashID1.ToString()));
        obj.push_back(Pair("hashid2", s.hashID2.ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listsidechainactivationstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listsidechainactivationstatus\n"
            "List activation status of all pending sidechains.\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechainactivationstatus", "")
            + HelpExampleRpc("listsidechainactivationstatus", "")
            );

    std::vector<SidechainActivationStatus> vStatus;
    vStatus = scdb.GetSidechainActivationStatus();

    UniValue ret(UniValue::VARR);
    for (const SidechainActivationStatus& s : vStatus) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", s.proposal.title));
        obj.push_back(Pair("description", s.proposal.description));
        obj.push_back(Pair("nage", s.nAge));
        obj.push_back(Pair("nfail", s.nFail));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listsidechainproposals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listsidechainproposals\n"
            "List your own cached sidechain proposals\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("listsidechainproposals", "")
            + HelpExampleRpc("listsidechainproposals", "")
            );

    std::vector<Sidechain> vProposal = scdb.GetSidechainProposals();
    UniValue ret(UniValue::VARR);
    for (const Sidechain& s : vProposal) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", s.title));
        obj.push_back(Pair("description", s.description));
        obj.push_back(Pair("nversion", s.nVersion));
        obj.push_back(Pair("hashid1", s.hashID1.ToString()));
        obj.push_back(Pair("hashid2", s.hashID2.ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue getsidechainactivationstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getsidechainactivationstatus\n"
            "List activation status for nSidechain.\n"
            "\nArguments:\n"
            "\nExamples:\n"
            + HelpExampleCli("getsidechainactivationstatus", "")
            + HelpExampleRpc("getsidechainactivationstatus", "")
            );

    std::vector<SidechainActivationStatus> vStatus;
    vStatus = scdb.GetSidechainActivationStatus();

    UniValue ret(UniValue::VARR);
    for (const SidechainActivationStatus& s : vStatus) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("title", s.proposal.title));
        obj.push_back(Pair("description", s.proposal.description));
        obj.push_back(Pair("nage", s.nAge));
        obj.push_back(Pair("nfail", s.nFail));
        obj.push_back(Pair("proposalhash", s.proposal.GetSerHash().ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue createsidechainproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 6)
        throw std::runtime_error(
            "createsidechainproposal\n"
            "Generates a sidechain proposal to be included in the next block " \
            "mined by this node.\n"\
            "Note that this will not broadcast the proposal to other nodes. " \
            "You must mine a block which includes your proposal to complete " \
            "the process.\n"\
            "Pending proposals created by this node will automatically be " \
            "included in the soonest block mined possible.\n"
            "\nArguments:\n"
            "1. \"nsidechain\"   (numeric, required) sidechain slot number\n"
            "2. \"title\"        (string, required) sidechain title\n"
            "3. \"description\"  (string, optional) sidechain description\n"
            "4. \"version\"      (numeric, optional) sidechain / proposal version\n"
            "5. \"hashid1\"      (string, optional) 256 bits used to identify sidechain\n"
            "6. \"hashid2\"      (string, optional) 160 bits used to identify sidechain\n"
            "\nExamples:\n"
            + HelpExampleCli("createsidechainproposal", "1 \"Namecoin\" \"Namecoin as a Bitcoin sidechain\" 0 78b140259d5626e17c4bf339c23cb4fa8d16d138f71d9803ec394bb01c051f0b 90869d013db27608c7428251c6755e5a1d9e9313")
            + "\n"
            + HelpExampleRpc("createsidechainproposal", "1 \"Namecoin\" \"Namecoin as a Bitcoin sidechain\" 0 78b140259d5626e17c4bf339c23cb4fa8d16d138f71d9803ec394bb01c051f0b 90869d013db27608c7428251c6755e5a1d9e9313")
            );

    int nSidechain = request.params[0].get_int();
    if (nSidechain < 0 || nSidechain > 255)
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

    std::string strTitle = request.params[1].get_str();

    std::string strDescription = "";
    if (request.params.size() >= 3)
        strDescription = request.params[2].get_str();

    int nVersion = -1;
    if (request.params.size() >= 4)
        nVersion = request.params[3].get_int();

    std::string strHashID1 = "";
    std::string strHashID2 = "";
    if (request.params.size() >= 5) {
        strHashID1 = request.params[4].get_str();
        if (strHashID1.size() != 64)
            throw JSONRPCError(RPC_MISC_ERROR, "HashID1 size invalid!");
    }
    if (request.params.size() == 6) {
        strHashID2 = request.params[5].get_str();
        if (strHashID2.size() != 40)
            throw JSONRPCError(RPC_MISC_ERROR, "HashID2 size invalid!");
    }

    if (strTitle.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Sidechain must have a title!");

    const uint8_t nSC = nSidechain;
    const unsigned char vchSC[1] = { nSC };

    std::vector<unsigned char> vch256;
    vch256.resize(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(&vchSC[0], 1).Finalize(&vch256[0]);

    CKey key;
    key.Set(vch256.begin(), vch256.end(), false);
    if (!key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CBitcoinSecret vchSecret(key);
    if (!vchSecret.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CPubKey pubkey = key.GetPubKey();
    if (!key.VerifyPubKey(pubkey))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Failed to verify pubkey");

    CKeyID vchAddress = pubkey.GetID();

    // Generate deposit script
    CScript sidechainScript = CScript() << OP_DUP << OP_HASH160 << ToByteVector(vchAddress) << OP_EQUALVERIFY << OP_CHECKSIG;

    Sidechain proposal;
    proposal.nSidechain = nSidechain;
    proposal.title = strTitle;
    proposal.description = strDescription;
    if (nVersion >= 0)
        proposal.nVersion = nVersion;
    else
        proposal.nVersion = 0;
    if (!strHashID1.empty())
        proposal.hashID1 = uint256S(strHashID1);
    if (!strHashID2.empty())
        proposal.hashID2 = uint160S(strHashID2);

    // Cache proposal so that it can be added to the next block we mine
    scdb.CacheSidechainProposals(std::vector<Sidechain>{proposal});

    // Cache the hash of the sidechain to ACK it
    scdb.CacheSidechainHashToAck(proposal.GetSerHash());

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("nSidechain", proposal.nSidechain));
    obj.push_back(Pair("title", proposal.title));
    obj.push_back(Pair("description", proposal.description));
    obj.push_back(Pair("version", proposal.nVersion));
    obj.push_back(Pair("hashID1", proposal.hashID1.ToString()));
    obj.push_back(Pair("hashID2", proposal.hashID2.ToString()));

    return obj;
}

UniValue setwithdrawalvote(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "setwithdrawalvote\n"
            "Set custom vote for sidechain Withdrawal.\n"
            "\nArguments:\n"
            "1. vote (\"upvote\"/\"downvote\"/\"abstain\")  (string, required) Vote\n"
            "2. nsidechain                            (numeric, required) Sidechain number of Withdrawal\n"
            "3. hash                                  (string, optional) Hash of the withdrawal\n"
            "\nExamples:\n"
            + HelpExampleCli("setwithdrawalvote", "")
            + HelpExampleRpc("setwithdrawalvote", "")
            );

    std::string strVote = request.params[0].get_str();
    if (strVote != "upvote" && strVote != "downvote" && strVote != "abstain")
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid vote (must be \"upvote\", \"downvote\" or \"abstain\")");

    // nSidechain
    int nSidechain = request.params[1].get_int();

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    if (strVote == "upvote" && request.params.size() != 3)
        throw JSONRPCError(RPC_TYPE_ERROR, "Withdrawal hash required for upvote");

    std::string strHash = "";
    if (request.params.size() == 3) {
        strHash = request.params[2].get_str();
        if (strHash.size() != 64)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash length");
    }

    uint256 hash = uint256S(strHash);
    if (request.params.size() == 3 && hash.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash");

    // Get current votes
    std::vector<std::string> vVote = scdb.GetVotes();

    if (strVote == "upvote")
        vVote[nSidechain] = strHash;
    else
    if (strVote == "downvote")
        vVote[nSidechain] = SCDB_DOWNVOTE;
    else
    if (strVote == "abstain")
        vVote[nSidechain] = SCDB_ABSTAIN;

    if (!scdb.CacheCustomVotes(vVote))
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to cache withdrawal votes!");

    return NullUniValue;
}

UniValue clearwithdrawalvotes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "clearwithdrawalvotes\n"
            "Delete all custom Withdrawal vote(s).\n"
            "\nExamples:\n"
            + HelpExampleCli("clearwithdrawalvotes", "")
            + HelpExampleRpc("clearwithdrawalvotes", "")
            );

    scdb.ResetWithdrawalVotes();

    return NullUniValue;
}

UniValue listwithdrawalvotes(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listwithdrawalvotes\n"
            "List custom votes for sidechain Withdrawal(s).\n"
            "\nExamples:\n"
            + HelpExampleCli("listwithdrawalvotes", "")
            + HelpExampleRpc("listwithdrawalvotes", "")
            );

    UniValue ret(UniValue::VARR);

    std::vector<std::string> vVote = scdb.GetVotes();
    for (size_t i = 0; i < vVote.size(); i++) {
        std::string strVote = "";
        if (vVote[i].size() == 64)
            strVote = vVote[i];
        else
        if (vVote[i].front() == SCDB_DOWNVOTE)
            strVote = "Downvote";
        else
        if (vVote[i].front() == SCDB_ABSTAIN)
            strVote = "Abstain";

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("nSidechain", i));
        obj.push_back(Pair("vote", strVote));
        ret.push_back(obj);
    }

    return ret;
}

UniValue getaveragefee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "getaveragefee\n"
            "\nArguments:\n"
            "1. block_count     (numeric, optional, default=6) number of blocks to scan\n"
            "2. start_height    (numeric, optional, default=current block count) block height to start from\n"
            "\nResult:\n"
            "{\n"
            "  \"fee\" : x.x,   (numeric) average of fees in " + CURRENCY_UNIT + "/kB\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getaveragefee", "6 10")
            );

    int nBlocks = 6;
    if (request.params.size() >= 1)
        nBlocks = request.params[0].get_int();

    int nHeight = chainActive.Height();
    if (request.params.size() == 2) {
        int nHeightIn = request.params[1].get_int();
        if (nHeightIn > nHeight)
            throw JSONRPCError(RPC_MISC_ERROR, "Invalid start height!");

        nHeight = nHeightIn;
    }

    if (nBlocks > nHeight)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid number of blocks!");

    int nTx = 0;
    CAmount nTotalFees = 0;
    for (int i = nHeight; i >= (nHeight - nBlocks); i--) {
        uint256 hashBlock = chainActive[i]->GetBlockHash();

        if (mapBlockIndex.count(hashBlock) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlock block;
        CBlockIndex* pblockindex = mapBlockIndex[hashBlock];
        if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
            throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");

        if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
            throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");

        // We don't have the coins (they are spent) to look up the transaction
        // input amounts for calculation of fees. Instead, get the block subsidy
        // for the height and subtract it from the coinbase output amount to
        // estimate fees paid in the block.
        CAmount nSubsidy = GetBlockSubsidy(i, Params().GetConsensus());
        CAmount nCoinbase = block.vtx[0]->GetValueOut();

        // Record total fees in the block
        nTotalFees += nCoinbase - nSubsidy;
        // Record number of transactions
        nTx += block.vtx.size();
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("feeaverage", ValueFromAmount(nTotalFees / nTx)));
    return result;
}

UniValue getworkscore(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "getworkscore \"nsidechain\" \"hash\")\n"
            "Request the workscore of a Withdrawal\n"
            "\nArguments:\n"
            "1. nsidechain     (numeric, required) Sidechain number to look up Withdrawal of\n"
            "2. hash           (string, required) Hash of the Withdrawal\n"
            "\nResult:\n"
            "{\n"
            "  \"workscore\" : x,   (numeric) workscore of Withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getworkscore", "0 hash")
            );

    // nSidechain
    int nSidechain = request.params[0].get_int();

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    std::string strHash = request.params[1].get_str();
    if (strHash.size() != 64)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash length");

    uint256 hash = uint256S(strHash);
    if (hash.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash");

    std::vector<SidechainWithdrawalState> vState = scdb.GetState(nSidechain);
    if (vState.empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "No Withdrawal(s) in SCDB for sidechain");

    int nWorkScore = -1;
    for (const SidechainWithdrawalState& s : vState) {
        if (s.hash == hash) {
            nWorkScore = s.nWorkScore;
            break;
        }
    }

    if (nWorkScore == -1)
        throw JSONRPCError(RPC_TYPE_ERROR, "No Withdrawal workscore in SCDB");

    return nWorkScore;
}

UniValue listwithdrawalstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listwithdrawalstatus \"nsidechain\")\n"
            "Request the workscore of a Withdrawal\n"
            "\nArguments:\n"
            "1. nsidechain     (numeric, required) Sidechain number to look up Withdrawal(s) of\n"
            "\nResult:\n"
            "{\n"
            "  \"hash\" : (string) hash of Withdrawal\n"
            "  \"nblocksleft\" : x, (numeric) verification blocks remaining\n"
            "  \"workscore\" : x, (numeric) workscore of Withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getworkscore", "0 hash")
            );

    // nSidechain
    int nSidechain = request.params[0].get_int();

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    std::vector<SidechainWithdrawalState> vState = scdb.GetState(nSidechain);
    if (vState.empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "No Withdrawal(s) in SCDB for sidechain");

    UniValue ret(UniValue::VARR);
    for (const SidechainWithdrawalState& s : vState) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("hash", s.hash.ToString()));
        obj.push_back(Pair("nblocksleft", s.nBlocksLeft));
        obj.push_back(Pair("nworkscore", s.nWorkScore));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listcachedwithdrawaltx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listcachedwithdrawaltx\n"
            "List my cached Withdrawal(s) for nSidechain\n"
            "\nArguments:\n"
            "1. nsidechain     (numeric, required) Sidechain number to list Withdrawal(s) of\n"
            "\nResult: (array)\n"
            "{\n"
            "  \"hash\" : x (string) hash of Withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("listcachedwithdrawaltransactions", "0")
            );

    // nSidechain
    int nSidechain = request.params[0].get_int();

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    std::vector<std::pair<uint8_t, CMutableTransaction>> vWithdrawal;
    vWithdrawal = scdb.GetWithdrawalTxCache();

    if (vWithdrawal.empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "No withdrawal bundle txns cached for sidechain");

    UniValue ret(UniValue::VARR);
    for (auto const& i : vWithdrawal) {
        if (i.first != nSidechain)
            continue;

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("hash", i.second.GetHash().ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue havespentwithdrawal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "havespentwithdrawal\n"
            "Return whether this Withdrawal was spent\n"
            "\nResult: true | false \n"
            "\nExample:\n"
            + HelpExampleCli("havespentwithdrawal", "hash, nsidechain")
            );

    std::string strHash = request.params[0].get_str();
    if (strHash.size() != 64)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash length");

    uint256 hash = uint256S(strHash);
    if (hash.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash");

    int nSidechain = request.params[1].get_int();

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    bool fSpent = scdb.HaveSpentWithdrawal(hash, nSidechain);

    return fSpent;
}

UniValue havefailedwithdrawal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "havefailedwithdrawal\n"
            "Return whether this Withdrawal failed\n"
            "\nResult: true | false \n"
            "\nExample:\n"
            + HelpExampleCli("havefailedwithdrawal", "hash, nsidechain")
            );

    std::string strHash = request.params[0].get_str();
    if (strHash.size() != 64)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash length");

    uint256 hash = uint256S(strHash);
    if (hash.IsNull())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Withdrawal hash");

    int nSidechain = request.params[1].get_int();

    if (!scdb.IsSidechainActive(nSidechain))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid Sidechain number");

    bool fFailed = scdb.HaveFailedWithdrawal(hash, nSidechain);

    return fFailed;
}

UniValue listspentwithdrawals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "listspentwithdrawals\n"
            "List Withdrawal(s) which have been approved by workscore and spent\n"
            "\nResult: (array)\n"
            "{\n"
            "  \"nsidechain\" : (numeric) Sidechain number of Withdrawal\n"
            "  \"hash\" : (string) hash of Withdrawal\n"
            "  \"hashblock\"   : (string) hash of block Withdrawal was spent in\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("listspentwithdrawals", "")
            );

    std::vector<SidechainSpentWithdrawal> vSpent = scdb.GetSpentWithdrawalCache();
    if (vSpent.empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "No spent Withdrawal(s) in cache!");

    UniValue ret(UniValue::VARR);
    for (const SidechainSpentWithdrawal& s : vSpent) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("nsidechain", s.nSidechain));
        obj.push_back(Pair("hash", s.hash.ToString()));
        obj.push_back(Pair("hashblock", s.hashBlock.ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue listfailedwithdrawals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "listfailedwithdrawals\n"
            "List Withdrawal(s) which have failed\n"
            "\nResult: (array)\n"
            "{\n"
            "  \"nsidechain\" : (numeric) Sidechain number of Withdrawal\n"
            "  \"hash\" : (string) hash of withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("listfailedwithdrawals", "")
            );

    std::vector<SidechainFailedWithdrawal> vFailed = scdb.GetFailedWithdrawalCache();
    if (vFailed.empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "No failed Withdrawal(s) in cache!");

    UniValue ret(UniValue::VARR);
    for (const SidechainFailedWithdrawal& f : vFailed) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("nsidechain", f.nSidechain));
        obj.push_back(Pair("hash", f.hash.ToString()));

        ret.push_back(obj);
    }

    return ret;
}

UniValue gettotalscdbhash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "gettotalscdbhash\n"
            "Get hash of every member of SCDB combined.\n"
            );

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hashscdbtotal", scdb.GetTestHash().ToString()));

    return ret;
}

UniValue getscdbdataforblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getscdbdataforblock\n"
            "Get SCDB data from leveldb for the specified block hash\n"
            "\nResult:\n"
            "\"nsidechains\" : (numeric) Number of active sidechains\n"
            "\nArray of Withdrawal status\n"
            "{\n"
            "  \"nsidechain\"  : (numeric) Sidechain number of Withdrawal\n"
            "  \"nblocksleft\" : (numeric) Blocks remaining to validate Withdrawal\n"
            "  \"nworkscore\"  : (numeric) Number of ACK(s) Withdrawal has received\n"
            "  \"hash\" : (string) hash of withdrawal\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getscdbdataforblock", "hashblock")
            );


    uint256 hashBlock = uint256S(request.params[0].get_str());

    LOCK(cs_main);

    BlockMap::iterator it = mapBlockIndex.find(hashBlock);
    if (it == mapBlockIndex.end()) {
        std::string strError = "Block hash not found";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    CBlockIndex* pblockindex = it->second;
    if (pblockindex == NULL) {
        std::string strError = "Block index null";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    SidechainBlockData data;
    if (!psidechaintree->GetBlockData(hashBlock, data))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't find data for block.");

    UniValue ret(UniValue::VARR);
    UniValue obj(UniValue::VOBJ);
    ret.push_back(obj);
    for (auto& x : data.vWithdrawalStatus) {
        for (auto& y : x) {
            UniValue obj(UniValue::VOBJ);
            obj.push_back(Pair("nsidechain", y.nSidechain));
            obj.push_back(Pair("nblocksleft", y.nBlocksLeft));
            obj.push_back(Pair("nworkscore", y.nWorkScore));
            obj.push_back(Pair("withdrawalbundle", y.hash.ToString()));
            ret.push_back(obj);
        }
    }

    // TODO print vActivationStatus
    // TODO print vSidechain

    return ret;
}

UniValue listfailedbmm(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "listfailedbmm\n"
            "Print the list of failed BMM transactions yet to be abandoned.\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\" : (string) Failed BMM txid.\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("listfailedbmm", "")
            );

    std::set<uint256> setTxid = scdb.GetRemovedBMM();

    UniValue ret(UniValue::VARR);
    for (const uint256& u : setTxid) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("txid", u.ToString()));
        ret.push_back(obj);
    }

    return ret;
}

UniValue getopreturndata(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getopreturndata\n"
            "Print OP_RETURN data for block.\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\"   : (string) transaction id\n"
            "  \"size\"   : (numeric) transaction size.\n"
            "  \"fees\"   : (numeric) transaction fees.\n"
            "  \"hex\"    : (string) hex from output.\n"
            "  \"decode\" : (string) decoded hex.\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getopreturndata", "")
            );

    uint256 hashBlock = uint256S(request.params[0].get_str());

    BlockMap::iterator it = mapBlockIndex.find(hashBlock);
    if (it == mapBlockIndex.end()) {
        std::string strError = "Block hash not found";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    CBlockIndex* pblockindex = it->second;
    if (pblockindex == NULL) {
        std::string strError = "Block index null";
        LogPrintf("%s: %s\n", __func__, strError);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    }

    std::vector<OPReturnData> vData;
    if (!popreturndb->GetBlockData(hashBlock, vData))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't find data for block.");

    UniValue ret(UniValue::VARR);
    for (const OPReturnData& d : vData) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("txid", d.txid.ToString()));
        obj.push_back(Pair("size", (uint64_t)d.nSize));
        obj.push_back(Pair("fees", FormatMoney(d.fees)));
        obj.push_back(Pair("hex", HexStr(d.script.begin(), d.script.end(), false)));

        std::string strDecode;
        for (const unsigned char& c : d.script) {
            strDecode += c;
        }
        obj.push_back(Pair("decode", strDecode));

        ret.push_back(obj);
    }

    return ret;
}

UniValue getactivesidechaincount(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "getactivesidechaincount\n"
            "Count number of active sidechains.\n"
            "\nResult:\n"
            "{\n"
            "  \"count\"   : (number) number of active sidechains\n"
            "}\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getactivesidechaincount", "")
            );

    int count = scdb.GetActiveSidechainCount();

    return count;
}

UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "echo|echojson \"message\" ...\n"
            "\nSimply echo back the input arguments. This command is for testing.\n"
            "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in"
            "drivechain-cli and the GUI. There is no server-side difference."
        );

    return request.params;
}

static UniValue getinfo_deprecated(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_METHOD_NOT_FOUND,
        "getinfo\n"
        "\nThis call was removed in version 0.16.0. Use the appropriate fields from:\n"
        "- getblockchaininfo: blocks, difficulty, chain\n"
        "- getnetworkinfo: version, protocolversion, timeoffset, connections, proxy, relayfee, warnings\n"
        "- getwalletinfo: balance, keypoololdest, keypoolsize, paytxfee, unlocked_until, walletversion\n"
        "\ndrivechain-cli has the option -getinfo to collect and format these in the old format."
    );
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getmemoryinfo",          &getmemoryinfo,          {"mode"} },
    { "control",            "logging",                &logging,                {"include", "exclude"}},
    { "util",               "validateaddress",        &validateaddress,        {"address"} }, /* uses wallet if enabled */
    { "util",               "createmultisig",         &createmultisig,         {"nrequired","keys"} },
    { "util",               "verifymessage",          &verifymessage,          {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, {"privkey","message"} },

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            {"timestamp"}},
    { "hidden",             "echo",                   &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "getinfo",                &getinfo_deprecated,     {}},

    /* Drivechain rpc commands for the user and sidechains */
    { "Drivechain",  "addwithdrawal",                 &addwithdrawal,                   {"nsidechain", "hash"}},
    { "Drivechain",  "createcriticaldatatx",          &createcriticaldatatx,            {"amount", "height", "criticalhash"}},
    { "Drivechain",  "listsidechainctip",             &listsidechainctip,               {"nsidechain"}},
    { "Drivechain",  "listsidechaindeposits",         &listsidechaindeposits,           {"nsidechain"}},
    { "Drivechain",  "countsidechaindeposits",        &countsidechaindeposits,          {"nsidechain"}},
    { "Drivechain",  "receivewithdrawalbundle",       &receivewithdrawalbundle,         {"nsidechain","rawtx"}},
    { "Drivechain",  "verifybmm",                     &verifybmm,                       {"blockhash", "bmmhash", "nsidechain"}},
    { "Drivechain",  "verifydeposit",                 &verifydeposit,                   {"blockhash", "txid", "ntx"}},
    { "Drivechain",  "listpreviousblockhashes",       &listpreviousblockhashes,         {}},
    { "Drivechain",  "listactivesidechains",          &listactivesidechains,            {}},
    { "Drivechain",  "listsidechainactivationstatus", &listsidechainactivationstatus,   {}},
    { "Drivechain",  "listsidechainproposals",        &listsidechainproposals,          {}},
    { "Drivechain",  "getsidechainactivationstatus",  &getsidechainactivationstatus,    {}},
    { "Drivechain",  "createsidechainproposal",       &createsidechainproposal,         {"nsidechain", "title", "description", "keyhash", "nversion", "hashid1", "hashid2"}},
    { "Drivechain",  "clearwithdrawalvotes",          &clearwithdrawalvotes,            {}},
    { "Drivechain",  "setwithdrawalvote",             &setwithdrawalvote,               {"vote", "nsidechain", "hashwithdrawal"}},
    { "Drivechain",  "listwithdrawalvotes",           &listwithdrawalvotes,             {}},
    { "Drivechain",  "getaveragefee",                 &getaveragefee,                   {"numblocks", "startheight"}},
    { "Drivechain",  "getworkscore",                  &getworkscore,                    {"nsidechain", "hashwithdrawal"}},
    { "Drivechain",  "havespentwithdrawal",           &havespentwithdrawal,             {"hashwithdrawal", "nsidechain"}},
    { "Drivechain",  "havefailedwithdrawal",          &havefailedwithdrawal,            {"hashwithdrawal", "nsidechain"}},
    { "Drivechain",  "listcachedwithdrawaltx",        &listcachedwithdrawaltx,          {"nsidechain"}},
    { "Drivechain",  "listwithdrawalstatus",          &listwithdrawalstatus,            {"nsidechain"}},
    { "Drivechain",  "listspentwithdrawals",          &listspentwithdrawals,            {}},
    { "Drivechain",  "listfailedwithdrawals",         &listfailedwithdrawals,           {}},
    { "Drivechain",  "gettotalscdbhash",              &gettotalscdbhash,                {}},
    { "Drivechain",  "getscdbdataforblock",           &getscdbdataforblock,             {"blockhash"}},
    { "Drivechain",  "listfailedbmm",                 &listfailedbmm,                   {}},
    { "Drivechain",  "getactivesidechaincount",       &getactivesidechaincount,         {}},

    /* Coin News RPC */
    { "CoinNews",    "getopreturndata",               &getopreturndata,                 {"blockhash"}},

};

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
