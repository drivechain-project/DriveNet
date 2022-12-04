#!/bin/bash

# This script will:
# !!!Delete old bitcoin data directory!!!
# Create a new bitcoin data directory & configuration file
# Use the RPC interface to generate a chain with transactions
# Shutdown
# Reindex in daemon mode, and measure how long it takes

clear

echo -e "\e[1mREAD: YOUR BITCOIN DATA DIRECTORY WILL BE DELETED\e[0m"
echo
echo "Your bitcoin data directory ~/.bitcoin will be deleted"
echo
echo -e "\e[31mWARNING: THIS WILL DELETE YOUR BITCOIN DATA!\e[0m"
echo
echo -e "\e[32mYou should probably run this in a VM\e[0m"
echo
read -p "Are you sure you want to run this? (yes/no): " WARNING_ANSWER
if [ "$WARNING_ANSWER" != "yes" ]; then
    exit
fi

#
# Remove old data directory
#
rm -rf ~/.bitcoin

#
# Create configuration file
#

echo
echo "Creating bitcoin configuration file"
mkdir ~/.bitcoin/
touch ~/.bitcoin/bitcoin.conf
echo "rpcuser=satoshi" > ~/.bitcoin/bitcoin.conf
echo "rpcpassword=measure" >> ~/.bitcoin/bitcoin.conf
echo "server=1" >> ~/.bitcoin/bitcoin.conf

# Start bitcoin qt so we can watch this part
echo
echo "Waiting for bitcoin to start"
./src/qt/bitcoin-qt --connect=0 &
sleep 5s

echo
echo "Checking if bitcoin has started"

# Test that bitcoin can receive commands and has 0 blocks
GETINFO=`./src/bitcoin-cli getmininginfo`
COUNT=`echo $GETINFO | grep -c "\"blocks\": 0"`
if [ "$COUNT" -eq 1 ]; then
    echo
    echo "bitcoin up and running!"
else
    echo
    echo "ERROR failed to send commands to bitcoin or block count non-zero"
    exit
fi

echo
echo "Bitcoin will now generate first 1000 blocks"
sleep 3s

# Generate 100 blocks
./src/bitcoin-cli generate 1000

# Check that 100 blocks were mined
COUNT=`./src/bitcoin-cli getblockcount`
if [ "$COUNT" -eq 1000 ]; then
    echo
    echo "Bitcoin has mined first 1000 blocks"
else
    echo
    echo "Bitcoin failed to mine first 1000 blocks!"
    exit
fi


# Start reading block txns from json and creating chain

echo
echo "Now we will read block data from json!"
sleep 1s

NUM_BLOCKS=`jq '.["blocks"]' blocks.json | jq length`

echo
echo "Found $NUM_BLOCKS blocks in json!"
sleep 1s

# Loop through json array of blocks which contain a json array of transactions
# that we want to put in the chain. Create the transactions and mine the block
for ((x = 0; x < $NUM_BLOCKS; x++)); do
    BLOCK=$((x+1))
    echo
    echo "Adding block data $BLOCK / $NUM_BLOCKS"
    sleep 1s

    NUM_TX=`jq -r --argjson x "$x" '.["blocks"][$x]["txn"]' blocks.json | jq length`
    echo "Block $x should have $NUM_TX txns"

    # Create transactions that should be in this block
    for ((y = 0; y < $NUM_TX; y++)); do
        AMOUNT=`jq -r --argjson x "$x" --argjson y "$y" '.["blocks"][$x]["txn"][$y]["amount"]' blocks.json`
        DEST=`jq -r --argjson x "$x" --argjson y "$y" '.["blocks"][$x]["txn"][$y]["dest"]' blocks.json`

        TXID=`./src/bitcoin-cli sendtoaddress $DEST $AMOUNT`
        echo "Tx: $TXID ([$x][$y]: $AMOUNT btc -> $DEST)"
    done

    # Mine block
    echo "Mining block!"
    ./src/bitcoin-cli generate 1
    sleep 1s
done


HEIGHT=`./src/bitcoin-cli getblockcount`
echo
echo "Getting block stats"
for ((x = 0; x < $NUM_BLOCKS; x++)); do
    HASH=`./src/bitcoin-cli getblockhash $((HEIGHT-x))`
    echo
    echo "Block $((HEIGHT-x)) : $HASH"

    BLOCK=`./src/bitcoin-cli getblock $HASH`
    WEIGHT=`echo $BLOCK | jq '.["weight"]'`
    SIZE=`echo $BLOCK | jq '.["size"]'`
    echo "weight: $WEIGHT weight units"
    echo "serialized size: $SIZE bytes"
done

echo
echo "Now we will shut down bitcoin & measure reindexing"
echo

# Shutdown bitcoin qt
./src/bitcoin-cli stop

sleep 5s

# Reindex using bitcoind
./src/bitcoind --connect=0 --reindex
