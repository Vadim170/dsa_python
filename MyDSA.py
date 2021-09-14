import hashlib
import random
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5 import uic


def digitsN(n, b):
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits


def modexp_lr_k_ary(a, b, n, k=5):
    base = 2 << (k - 1)
    # Предварительно вычислим таблицу показателей
    table = [1] * base
    for i in range(1, base):
        table[i] = table[i - 1] * a % n
    # Точно так же, как двоичный метод ЛР, только с другой базой
    r = 1
    for digit in reversed(digitsN(b, base)):
        for i in range(k):
            r = r * r % n
        if digit:
            r = r * table[digit] % n
    return r


def verify(r, s, g, p, q, y, message):
    if (r <= 0) or (r >= q) or (s <= 0) or (s >= q): return False
    w = modexp_lr_k_ary(s, q - 2, q)
    u1 = (message * w) % q
    u2 = (r * w) % q
    # v = (((g**u1)*(y**u2)) % p ) % q # правильная формула, но медленная
    # Поэтому мы используем арифметику по модулю для вычисления промежуточных значений:
    u1 = pow(g, u1, p)
    u2 = pow(y, u2, p)
    v = u1 * u2 % p % q
    return v == r


class MyForm(QMainWindow):
    # 160-bit sha-1
    dsa_key = {
        "q": 1218442816993522937915646204915776994404649089503,
        "P": 11220611807188583130302963536190351192186270126479330588604287699892081267588448305835704397593153801135202051719876685351614175538253684346816652027037363,
        "G": 11189361631195852088154673407566885728548496486362662112597687161142104619469702160215294558351391466982303919803857229515093575816938371433954759500448775,
        "Y": 4572510396595314270786423212039255215498677297795049756997099191729339616558419010431226927123876238239229467750410441342637393785565872285607741290303779,
        "X": 148102768779017960166999813987055538077373228390
    }

    def calculate(self):
        M = self.ui.eMessageSender.toPlainText()
        m = hashlib.sha1()
        m.update(M.encode('ascii'))
        print("m =", m.hexdigest())
        m = int("0x" + m.hexdigest(), 0)

        x = int(self.ui.eX.text())
        g = int(self.ui.eG.text())
        p = int(self.ui.eP.text())
        q = int(self.ui.eQ.text())

        while True:
            k = random.randrange(1, q - 1)
            modexp = modexp_lr_k_ary(g, k, p)
            r = modexp % q
            if r == 0: continue
            k1 = modexp_lr_k_ary(k, q - 2, q) * (m + x * r)
            s = k1 % q
            if s == 0: continue
            break

        self.ui.eMessageGetter.setPlainText(M)
        self.ui.eR.setText(str(r))
        self.ui.eS.setText(str(s))

    def check(self):
        M = self.ui.eMessageGetter.toPlainText()
        m = hashlib.sha1()
        m.update(M.encode('ascii'))
        m = int("0x" + m.hexdigest(), 0)
        print("m =", m)

        r = int(self.ui.eR.text())
        s = int(self.ui.eS.text())
        y = int(self.ui.eY.text())
        g = int(self.ui.eG.text())
        p = int(self.ui.eP.text())
        q = int(self.ui.eQ.text())

        lbl = self.ui.lblValid
        if verify(r, s, g, p, q, y, m):
            lbl.setText("Подпись верна")
        else:
            lbl.setText("Подпись неверна")

    def calculateY(self):
        g = int(self.ui.eG.text())
        p = int(self.ui.eP.text())
        x = int(self.ui.eX.text())
        y = g ** x % p
        self.ui.eY.setText(str(y))

    def __init__(self, parent=None):
        QMainWindow.__init__(self)
        self.ui = uic.loadUi('MyDSA_window.ui')
        self.ui.show()

        # Привязка событий
        self.ui.btnSend.clicked.connect(self.calculate)
        self.ui.btnCheck.clicked.connect(self.check)
        self.ui.btnCalculateY.clicked.connect(self.calculateY)

        x = self.dsa_key["X"]
        self.ui.eX.setText(str(x))

        q = self.dsa_key["q"]
        p = self.dsa_key["P"]
        g = self.dsa_key["G"]
        y = self.dsa_key["Y"]

        self.ui.eQ.setText(str(q))
        self.ui.eP.setText(str(p))
        self.ui.eG.setText(str(g))
        self.ui.eY.setText(str(y))

        M = "Hello world!"
        self.ui.eMessageSender.setText(M)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    myapp = MyForm()
    sys.exit(app.exec_())



