Tool/model and date:
ChatGPT, 6.1 Sol, October 2, 2026.

Purpose:
Help with planning, understanding the assignment, writing Python code,
and debugging.

AI Conversation Log files:
ai_conversation.txt

What I used:
python3 --version
openssl version
pip show cryptography pytest

openssl genpkey -genparam -algorithm DH \
  -pkeyopt group:ffdhe3072 -out ffdhe3072.pem

openssl dhparam -in ffdhe3072.pem -text -noout | head -3
I also sent error messages to debug and also used it for planning out the assignment.
I used code generated from ChatGPT to create baseline.py and handshake.py

How I tested it:
I tested the code and commands by checking which versions of software I downloaded and also by making sure that all tests passed and creating files to store the evidence in.

One error, limitation, or rejected suggestion:
The AI didnt follow the 16 byte restriction to avoid overlapping the CTR counter blocks so I had to make sure the plaintext bytes aligned with the assignments prescribed IV format.

