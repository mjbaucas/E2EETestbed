from matplotlib import pyplot as plt

dataX = ["1M","2M","3M","4M","5M","6M","7M","8M","9M","10M"]

aes_rsa = [0.0016, 0.0025, 0.0033, 0.0043, 0.0053, 0.0067, 0.0079, 0.0084, 0.0102, 0.0106]
aes_ecc = [0.0013, 0.0021, 0.0031, 0.0041, 0.0051, 0.0062, 0.0071, 0.0081, 0.0096, 0.0104]
cha_rsa = [0.0024, 0.0044, 0.0063, 0.0082, 0.0102, 0.0122, 0.0142, 0.0162, 0.0188, 0.0205]
cha_ecc = [0.0021, 0.0042, 0.0060, 0.0079, 0.0098, 0.0120, 0.0142, 0.0159, 0.0183, 0.0202]

def plot_data(dataX, aes_rsa, aes_ecc, cha_rsa, cha_ecc, name):
    plt.figure(dpi=500)
    plt.plot(dataX,aes_rsa,marker='s', ms=8, label="AES + RSA", color="purple")
    plt.plot(dataX,aes_ecc,marker='o', ms=8,label="AES + ECC", color="green")
    plt.plot(dataX,cha_rsa,marker='^', ms=8, label="ChaCha20 + RSA", color="darkcyan")
    plt.plot(dataX,cha_ecc,marker='*', ms=8,label="ChaCha20 + ECC", color="red")
    plt.xlabel("Character Length")
    plt.ylabel("Encryption Time (s)")
    plt.legend()
    plt.grid(linestyle = '--', linewidth = 0.5)
    plt.tight_layout()
    plt.savefig(name)

plot_data(dataX, aes_rsa, aes_ecc, cha_rsa, cha_ecc,'enc_time')
