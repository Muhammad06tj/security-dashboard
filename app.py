from flask import Flask, render_template, request 
import string
import hashlib
import secrets, time
import re
import email
#Function File Integrity Monitor_________________________________________________
def get_hash(filename):
	with open(filename, "rb") as f:
		content = f.read()
		return hashlib.sha256(content).hexdigest()

# Функция для Шифра Цезаря_____________________________________________________
def caesar(text, shift):
	result = ''
	for i in text:
		if i.isalpha():
			if i.isupper():     
				a = chr( (ord(i) - ord('A') + shift) % 26 + ord('A') )
			else:
				a = chr( (ord(i) - ord('a') + shift) % 26 + ord('a') )
			result += a
		else:
			result += i
	return result

#Function URL analyzer___________________________________________________________
def check_url(url):
	danger = 0
	if url.startswith('http://'):
		danger += 1
	domain = url.split('//')[1]
	domain = domain.split('/')[0]
	if domain[0].isdigit():
		danger += 1
	point = url.count('.')
	if point > 3:
		danger += 1
	dwords = ['free', 'winner', 'click', 'hack', 'login', 'secure']    
	for word in dwords:
		if word in url:
			danger += 1
	long = len(url)
	if long > 75:
		danger += 1
	return danger
#Function Identify_Hash_________________________________________________________
def identify_hash(hash_input):
	if hash_input.startswith('$2b$') or hash_input.startswith('$2a$'):
		return('bcrypt')
	elif len(hash_input) == 32:
		return('MD5')
	elif len(hash_input) == 40:
		return('SHA-1')
	elif len(hash_input) == 64:
		return('SHA-256')
	elif len(hash_input) == 128:
		return('SHA-512')
	else:
		return('Unknown')

app = Flask(__name__)
@app.route("/")
def index():
	return render_template("index.html")
#Проверка Пароля________________________________________________________________ 
@app.route("/password_Cheaker", methods=["GET", "POST"])
def password_Cheaker():
	if request.method == "POST":
		password = request.form.get("password")
		symbols = len(password)
		score = 0
		if symbols >= 8:
			score += 1
		if any(char in string.ascii_uppercase for char in password):
			score += 1
		if any(char in string.ascii_lowercase for char in password):
			score += 1
		if any(char in string.digits for char in password):
			score += 1
		if any(char in string.punctuation for char in password):
			score += 1
		if score == 1 or score == 2:
			result = ("Пароль слабый")
		if score == 3 or score == 4:
			result = ("Пароль средний")
		if score == 5:
			result = ("Пароль надежный")
		return render_template("password_cheaker.html", result = result )	
	return render_template("password_cheaker.html")
#Шифр Цезаря___________________________________________________________________
@app.route("/caesar_cipher", methods=["GET", "POST"])
def caesar_cipher():
	if request.method == "POST":
		text = request.form.get("text")
		sdvig = int(request.form.get("number"))
		result = caesar(text, sdvig)
		return render_template("caesar_cipher.html", result = result)
	return render_template("caesar_cipher.html")
#URL analyzer_________________________________________________________________
@app.route("/url_analyzer", methods=["GET", "POST"])
def url_analyzer():
	if request.method == "POST":
		url = request.form.get("url")
		result = check_url(url)
		if result > 3:
			result=("Опасный URL")
		elif result > 1:
			result=("Подозрительный URL")
		else:
			result=("Безопасный URL")
		return render_template("url_analyzer.html", result=result)
	return render_template("url_analyzer.html")
#Password_hashing_______________________________________________________________
@app.route("/password_hashing", methods=["GET", "POST"])
def password_hashing():
	if request.method == "POST":
		password = request.form.get("password")
		result = hashlib.sha256(password.encode()).hexdigest()
		return render_template("password_hashing.html", result=result)
	return render_template("password_hashing.html")
#Hash Indetifier________________________________________________________________
@app.route("/hash_identifier", methods=["GET", "POST"])
def hash_identifier():
	if request.method == "POST":
		hash = request.form.get("hash")
		result = identify_hash(hash)
		return render_template("identify_hash.html", result=result)
	return render_template("identify_hash.html")

#Phishing_Analyzer_____________________________________________________________
@app.route("/phishing_analyzer", methods=["GET", "POST"])
def phishing_analyzer():
	if request.method == "POST":
		link = request.form.get("link")
		phishing_words = ["срочно", "заблокирован", "пароль", "карта", "подтвердите"]
		score = 0
		urls = re.findall(r'http[s]?://\S+', link)
		for my_email in phishing_words:
			if my_email in link.lower():
				score += 1
		if "http://" in link:
			score += 1
		if score >= 2:
			result = ("Phishing")
		else:
			result = ("Safe")
		return render_template("phishing_analyzer.html", result=result)
	return render_template("phishing_analyzer.html")
#Phishing Email Headers________________________________________________________
@app.route("/email_headers", methods=["GET", "POST"])
def check_header():
	if request.method == "POST":
		head = request.form.get("head")
		msg = email.message_from_string(head)
		result = "Подозрительного не найдено"
		if msg['From'] and 'fake' in msg['From']:
			result = ("Подозрительный отправитель")
		if msg['Subject'] and 'заблокирован' in msg['Subject']:
			result = ("Подозрительная тема")

		return render_template("Phishing_email_headers.html", result=result)
	return render_template("Phishing_email_headers.html")
#File Integrity Monitor__________________________________________________________	
@app.route("/file_integrity", methods=["GET", "POST"])
def file_integrity():
	if request.method == "POST":
		file = request.files.get("file")
		hash = request.form.get("hash")
		file_hash = hashlib.sha256(file.read()).hexdigest()
		if file_hash == hash:
			result = ("Файл не изменен")
		else:
			result = ("Файл изменен")
		return render_template("File_integrity_monitor.html", result=result)
	return render_template("File_integrity_monitor.html")		



if __name__ == "__main__":
	app.run()

