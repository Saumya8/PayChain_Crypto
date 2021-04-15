from xml.etree.ElementTree import tostring

from flask import Flask, request, jsonify, render_template
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from Des_Encryption import des
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount

    def to_dict(self):
        print("function to_dict [class transaction]")
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })

    def sign_transaction(self):
        print("function [class transaction] sign_transaction")
        print(type(self.sender_private_key))

        # error bcoz of RSA before, now improved
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))

        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        sign_str = binascii.hexlify(signer.sign(h)).decode('ascii')
        print(sign_str)
        """
        # sign_des = des.creatingDesHash(sign_str[0:16]) + des.creatingDesHash(sign_str[16:32]) + 
        # des.creatingDesHash(sign_str[32:48]) + des.creatingDesHash(sign-str[48:64]) 
        """
        return binascii.hexlify(signer.sign(h)).decode('ascii')


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    print("function generate_transaction")
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)

    response = {'transaction': transaction.to_dict(),
                'signature': transaction.sign_transaction()}

    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    # private_key = RSA.generate(1024, random_gen)
    private_key = RSA.generate(1024, random_gen)
    # print(private_key)
    pk = binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii')
    private_key_str= pk
    public_key = private_key.publickey()
    pub_key_str = binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    """
    # pk_des = des.creatingDesHash("0123456789ABCDEF")
    # print(len("0123456789ABCDEF"))
    # print(len(pk[0:16]))
    # print(pk)
    # print(len(pk))
    # print(des.creatingDesHash(pk[0:64]))
    # print(binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'))
    private_key_des = des.creatingDesHash(pk[0:16]) + des.creatingDesHash(pk[16:32]) + des.creatingDesHash(pk[32:48]) + des.creatingDesHash(pk[48:64])
    print(private_key_des)
    print(len(private_key_des))
    pub_key_des = des.creatingDesHash(pub_key_str[0:16]) + des.creatingDesHash(pub_key_str[16:32]) + des.creatingDesHash(pub_key_str[32:48]) + des.creatingDesHash(pub_key_str[48:64])
    print(len(pub_key_str))
    """
    response = {
        'private_key': private_key_str,
        # binascii.hexlify(private_key_des.export_key(format('DER'))).decode('ascii'),
        'public_key': pub_key_str
    }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
