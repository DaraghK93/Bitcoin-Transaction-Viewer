### Bitcoin Transaction Parser

## To Run:

Ensure your IP address and port have been changed in the python file
These are the first variables in the code called myIP and myPort

If the peerIP is not online, change this to a valid PeerIP and Port

to run, open a terminal and change to the directory in which the file resides
and type 'python Assignment_3.py'

The program will tell you once it has connected to the peer and the messages should start to arrive

These will either be Transaction or Block messages.

Transactions will show information about the inputs and outputs, their amounts and the previous hashes for the inputs. Also shows is when the transaction will be unlocked or if it is locked at all

Blocks will show the previous block hash, the time of creation, the nonce and the no. of transactions on that block.
