
# Networkreat Detection System

## Introduction

This project is a network monitoring and threat detection system using the ARP protocol and port scanning. It utilizes Flask to create a web interface that displays connected devices and captured requests.

## Features

- **Detect connected devices:** Using fping.
- **Capture and analyze packets:** Using Scapy.
- **Log suspicious requests:** All requests are logged in a log file.
- **Interactive web interface:** Displays data in an organized and user-friendly manner.

## Requirements

- Python 3
- Flask
- Scapy
- fping
- nmap (for network scanning)

## Installation

1. First, try to install the necessary packages using `apt`:

```bash
sudo apt update
sudo apt install python3-nmap python3-scapy
```

2. If the packages are not available or installation fails, use `pip` to install them:

```bash
pip install flask scapy nmap
```

3. You may also want to create a virtual environment for better management of dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install nmap scapy flask
```

## Usage

1. Ensure all dependencies are installed.
2. Run the server using:

```bash
python scan.py
```

3. Open your browser and go to http://localhost:5000 to view the interface.

---

# Network Threat Detection System

## مقدمة

هذا المشروع هو نظام لمراقبة الشبكة واكتشاف التهديدات باستخدام بروتوكول ARP وفحص المنافذ. يعتمد على إطار عمل Flask لإنشاء واجهة ويب تعرض الأجهزة المتصلة والطلبات الملتقطة.

## المميزات

- **اكتشاف الأجهزة المتصلة بالشبكة:** باستخدام fping.
- **التقاط وتحليل الحزم:** باستخدام Scapy.
- **تسجيل الطلبات المشبوهة:** يتم تسجيل جميع الطلبات في ملف log.
- **واجهة ويب تفاعلية:** تعرض البيانات بشكل منظم وسهل الفهم.

## متطلبات التشغيل

- Python 3
- Flask
- Scapy
- fping
- nmap (لإجراء فحص الشبكة)

## التثبيت

1. أولاً، حاول تثبيت الحزم اللازمة باستخدام `apt`:

```bash
sudo apt update
sudo apt install python3-nmap python3-scapy
```

2. إذا لم تكن الحزم متوفرة أو فشلت عملية التثبيت، يمكنك استخدام `pip` لتثبيتها:

```bash
pip install flask scapy nmap
```

3. يمكنك أيضًا إنشاء بيئة افتراضية لإدارة الحزم بشكل أفضل:

```bash
python3 -m venv venv
source venv/bin/activate
pip install nmap scapy flask
```

## طريقة التشغيل

1. تأكد من تثبيت جميع المتطلبات.
2. قم بتشغيل الخادم باستخدام:

```bash
python scan.py
```

3. افتح المتصفح وانتقل إلى http://localhost:5000 لرؤية الواجهة.


# --------------MADE BY Sb3ly--------------
