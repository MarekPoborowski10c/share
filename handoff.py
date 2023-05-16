#!/usr/bin/python3
# python3 -m pip install web3==6.2.0 click==8.0.3

import click
from eth_account import Account
from web3 import Web3
from binascii import unhexlify

###############
# Constants
###############

# ORACLEA 0x8f8d3fe6c1770eff9acc35e65fa301b850ba3556
# ORACLEB 0xc8301820f1758833bb4bb9a320cca1fbf8ad8cac

def abi():
    return '[{"inputs": [{"internalType": "address", "name": "_newOracle", "type": "address"}], "name": "changeOracle", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"}]'

def defaultChainID():
    return 15

def defaultContract():
    return "0xdaf5578b754a621919804a1510b1f61515905f46"

def defaultImpersonate():
    return "0x0000000000000000000000000000000000000000"

def defaultURL():
    return ""

def defaultNonce():
    return -1

def defaultPassword():
    return ""

def defaultOracle():
    # this is the correct address for the new second factor service signer
    return "0x54ac818A95D7BD1FA7fC9E5DB6959f9D99B1164B"

###############
# CLI command handler
###############

@click.command()
@click.argument('keysrc', type=click.File('r'))
@click.option("-o", "--oracle", 
    default=defaultOracle(),
    help="The new oracle account to be set encoded as hex or checksummed address. The default value is the correct address for the new second factor service signer")
@click.option("-p", "--password", 
    prompt=True, 
    prompt_required=False, 
    hide_input=True, 
    default=defaultPassword(), 
    help="Prompt for password. Only use if private key is in an encrypted keyfile.")
@click.option("-n", "--nonce", 
    default=defaultNonce(), 
    help="Manually provide a nonce for the tx. If not passed --url must be set")
@click.option("-u", "--url", 
    default=defaultURL(), 
    help="JSONRPC endpoint URL. If -n set but -u not set, tx will print to term.")
@click.option("-i", "--chainid", 
    default=defaultChainID(), 
    type=click.INT, 
    help="The chainID of the target chain")
@click.option("-c", "--contract", 
    default=defaultContract(), 
    help="The chainID of the target chain")
@click.option("-e", "--execute", 
    is_flag=True, 
    help="Execution flag. Tx will only be printed to the terminal unless this flag is set")
@click.option("-I", "--impersonate",
    default=defaultImpersonate(),
    help="Impersonate an account for the tx. Only use this option if you are using Ganache under fork mode for testing.")
def handoff(keysrc, oracle, password, nonce, url, chainid, contract, execute, impersonate):
    """KEYSRC private key file containing raw hex or an Ethereum encrypted keyfile

    Note: Either a nonce or a JSONRPC url must be provided. If a nonce is provided, the tx will be signed and printed to the terminal. 
    If a JSONRPC url is provided, the tx will be signed and sent to the network.
    """
    # clean and validate inputs 
    nonce, url, password, impersonate = cleanArgs(nonce, url, password, impersonate)
    if nonce is None and url is None:
        click.echo("You must either provide a nonce or a JSONRPC url in order to use this script")
        click.exit()

    # parse keys, load provider, get/use nonce given, and build tx
    w3 = provider(url)
    oracle = cleanAddr(w3, oracle)
    ca = cleanAddr(w3, contract)
    acct, privk = loadkey(w3, keysrc, password)
    if nonce is None:
        nonce = getNonce(w3, acct)
    

    # build the tx and encode the data. we will not use this tx if impersonating an account
    # but we use this interface to encode the tx data
    c = w3.eth.contract(address=ca, abi=abi())

    if impersonate is not None:
        ia = cleanAddr(w3, impersonate)
        tx = c.functions.changeOracle(oracle).build_transaction({
            'chainId': chainid,
            'value': 0,
            'gas': 100_000,
            'gasPrice': 0,
            'nonce': nonce,
            'from': ia,
        })
        click.echo(f"Impersonated Transaction:\n    {tx}\n")
    else:
        tx = c.functions.changeOracle(oracle).build_transaction({
            'chainId': chainid,
            'value': 0,
            'gas': 100_000,
            'gasPrice': 0,
            'nonce': nonce,
        })
        #sign the transaction
        signed_tx = w3.eth.account.sign_transaction(tx, privk)
        click.echo(f"Raw Transaction:\n    {w3.to_hex(signed_tx.rawTransaction)}\n")
    

    # if execute and url set send the tx
    if url is not None and execute:
        hsh = None
        if impersonate is not None:
            hsh = w3.eth.send_transaction(tx)
        else:
            hsh = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        click.echo(f"Tx Hash:\n    {w3.to_hex(hsh)}\n")
        receipt = w3.eth.wait_for_transaction_receipt(hsh)
        click.echo("Transaction receipt mined:")
        click.echo(dict(receipt))
        click.echo("\nWas transaction successful?")
        click.echo(receipt["status"])

###############
# Helper functions
###############

def cleanArgs(nonce, url, password, impersonate):
    if nonce == defaultNonce():
        nonce = None
    if url == defaultURL():
        url = None
    if password == defaultPassword():
        password = None
    if impersonate == defaultImpersonate():
        impersonate = None
    return (nonce, url, password, impersonate)

def cleanHexString(d, isAccount=True):
    l = 64
    if isAccount:
        l = 40
    d = d.replace("\n", "").replace("0x", "").rjust(l, '0')
    return "".join(["0x", d])

def cleanKey(d):
    return unhexlify(cleanHexString(d, isAccount=False).replace("0x", ""))

def cleanAddr(w3, d):
    return w3.to_checksum_address(cleanHexString(d))

def loadkey(w3, keysrc, password):
    data = keysrc.read()
    privk = None
    if password is not None:
        privk = w3.eth.account.decrypt(data, password)
    if privk is None:
        privk = cleanKey(data)
    acct = Account.from_key(privk)
    return (acct, privk)

def provider(url):
    w3 = None
    if url is not None:
        return Web3(Web3.HTTPProvider(url))
    else:
        return Web3()

def getNonce(w3, acct):
    return w3.eth.get_transaction_count(acct.address) + 1

if __name__ == '__main__':
    handoff()
