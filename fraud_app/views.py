import time
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

@api_view(['POST'])
def crypto_login_api(request):
    data = request.data
    auth_mode = data.get('mode', 'rsa') # 'rsa', 'ecc', or 'hybrid'
    password = data.get('password', 'secret')
    
    start_time = time.time()
    result_message = ""
    
    try:
        if auth_mode == 'rsa':
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            
            ciphertext = public_key.encrypt(
                password.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result_message = "RSA Authentication Successful!"

        elif auth_mode == 'ecc':
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            
            signature = private_key.sign(
                password.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            public_key.verify(
                signature,
                password.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            result_message = "ECC Authentication Successful!"

        elif auth_mode == 'hybrid':
            # RSA Step
            rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rsa_pub = rsa_priv.public_key()
            enc_data = rsa_pub.encrypt(password.encode('utf-8'), padding.PKCS1v15())
            rsa_priv.decrypt(enc_data, padding.PKCS1v15())
            
            # ECC Step
            ecc_priv = ec.generate_private_key(ec.SECP256R1())
            ecc_pub = ecc_priv.public_key()
            sig = ecc_priv.sign(password.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
            ecc_pub.verify(sig, password.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
            
            result_message = "Hybrid (RSA + ECC) Authentication Successful!"
            
        else:
            return Response({"error": "Invalid Authentication Mode"}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    end_time = time.time()
    execution_time_ms = round((end_time - start_time) * 1000, 4)

    return Response({
        "status": "Success",
        "mode": auth_mode.upper(),
        "message": result_message,
        "execution_time_ms": execution_time_ms
    }, status=status.HTTP_200_OK)


from django.shortcuts import render

def home_view(request):
    return render(request, 'fraud_app/index.html')


from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['POST'])
def research_chatbot_api(request):
    user_message = request.data.get('message', '').lower()
    
    # Research Knowledge Base derived from Excel & Documents
    knowledge_base = {
        "psus": "Perceived Susceptibility (PSUS) has a path coefficient of 0.437 (T-statistic = 5.981), showing a strong positive impact on willingness to trust (WT) in e-commerce security.",
        "ps": "Perceived Severity (PS) has a path coefficient of 0.159 (T-statistic = 2.714), indicating how users evaluate the seriousness of identity theft.",
        "peff": "Perceived Effectiveness (PEFF) has a path coefficient of 0.129 (T-statistic = 2.036), highlighting the importance of security tools like 2FA and OTP.",
        "cost": "Perceived Cost (COST) has a path coefficient of 0.079 (T-statistic = 1.201), measuring user friction and time loss.",
        "rsa": "RSA-2048 is an asymmetric cryptographic algorithm used for secure credential transmission, though it has higher processing execution time.",
        "ecc": "Elliptic Curve Cryptography (ECC) provides security equivalent to RSA with smaller key sizes, resulting in significantly faster execution times.",
        "hybrid": "The Hybrid (RSA + ECC) model combines both cryptographic systems to achieve maximum security for critical e-commerce transactions.",
        "survey": "The survey was conducted among e-commerce and social media users above 17 years old to analyze machinative identity theft perceptions."
    }

    # Simple keyword matching intelligence
    response_text = "I am your research assistant bot. You can ask me about PLS-SEM path coefficients (PSUS, PS, PEFF, COST), security models (RSA, ECC, Hybrid), or survey details."
    
    for key, val in knowledge_base.items():
        if key in user_message:
            response_text = val
            break

    return Response({
        "reply": response_text
    })