# SimpleEncryption

[English below | English version below]

## 简介

SimpleEncryption 是一个基于 Qt 和 OpenSSL 的跨平台文件加密/解密工具，支持 AES-128-GCM 算法，界面简洁，操作简单。适合个人用户对敏感文件进行本地加密保护。

## 功能特性

- 支持文件加密与解密，采用 AES-128-GCM 算法
- 自动生成安全密钥，密钥需妥善保存
- 文件哈希校验（SHA256）
- 操作日志记录
- 跨平台（Windows、Linux、macOS）

## 构建方法

1. 安装 Qt 6（建议 6.8.3）和 OpenSSL
2. 克隆仓库：
   ```sh
   git clone https://github.com/mikufan39/SimpleEncryption.git
   ```
3. 使用 CMake 配置并生成工程文件：
   ```sh
   cd SimpleEncryption
   mkdir build
   cd build
   cmake ..
   ```
4. 使用 IDE（如 Qt Creator、Visual Studio）或命令行编译

## 使用说明

1. 打开程序，选择“加密文件”标签页
2. 选择要加密的文件，点击“开始”
3. 保存密钥，密钥丢失将无法解密
4. 解密时，选择加密文件并输入正确密钥

---

# SimpleEncryption

## Introduction

SimpleEncryption is a cross-platform file encryption/decryption tool based on Qt and OpenSSL, using AES-128-GCM algorithm. It features a simple UI and is suitable for personal file protection.

## Features

- File encryption and decryption with AES-128-GCM
- Secure random key generation (keep your key safe!)
- File hash verification (SHA256)
- Operation log
- Cross-platform (Windows, Linux, macOS)

## Build Instructions

1. Install Qt 6 (recommended: 6.8.3) and OpenSSL
2. Clone the repository:
   ```sh
   git clone https://github.com/mikufan39/SimpleEncryption.git
   ```
3. Configure with CMake:
   ```sh
   cd SimpleEncryption
   mkdir build
   cd build
   cmake ..
   ```
4. Build with your IDE (Qt Creator, Visual Studio) or command line

## Usage

1. Open the app and select the "Encrypt File" tab
2. Choose a file to encrypt and click "Start"
3. Save the generated key; you cannot decrypt without it!
4. To decrypt, select the encrypted file and enter the correct key

---

MIT License
