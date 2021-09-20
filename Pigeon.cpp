#include "Pigeon.h"

const auto installPath = "C:\\Pigeon.exe";
const auto udpPort = 8901;
const auto debug = false;

// 检查管理员权限
bool isElevated();

// 注册右键菜单
void addContentMenu(const std::string& type);

// 启动后台进程
void startDaemon();

// 遍历文件夹
std::vector<std::string> walkThrough(const std::string& path);

// 字符串替换函数
void replaceAll(std::string& str, const std::string& from, const std::string& to);

// 计算文件 MD5 摘要
std::string getFileMd5(const std::string& filePath);

struct fileInfo
{
	char md5[32];
	std::string name;
	unsigned long packCount;
	bool isDir;
};

struct packInfo
{
	char md5[32];
	unsigned long index;
	char data[512];
	int dataLength;
};

int main(int argc, char* argv[])
{
	// 无参数启动：复制程序至C盘，注册右键菜单，启动守护进程服务
	// 右键启动：检测文件类型，（打包目录），广播发送文件
	// 服务启动：接收文件
	// 卸载启动：注销右键菜单，删除C盘程序
	cxxopts::Options options("Pigeon", "局域网文件传输工具");
	options.add_options()
		("d,deliver", "发送文件")
		("f,file", "文件路径", cxxopts::value<std::string>())
		("s,serve", "启动服务")
		("u,uninstall", "卸载")
		;
	auto result = options.parse(argc, argv);
	if (result.count("deliver")) {
		if (result.count("file")) {
			// 发送指定文件
			auto& filePath = result["file"].as<std::string>();
			auto fileAttr = GetFileAttributesA(filePath.c_str());
			std::string fileToSend = "";
			if (fileAttr != INVALID_FILE_ATTRIBUTES) {
				if (fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
					// 目录文件需要先压缩
					auto files = walkThrough(filePath);
					auto parent = filePath.substr(0, filePath.rfind("\\"));
					miniz_cpp::zip_file archive;
					auto fileAmount = files.size();
					for each (auto file in files)
					{
						CHAR relative[MAX_PATH];
						PathRelativePathToA(relative, parent.c_str(), fileAttr, file.c_str(), GetFileAttributesA(file.c_str()));
						auto arcPath = std::string(relative);
						replaceAll(arcPath, ".\\", "");
						replaceAll(arcPath, "\\", "/");
						archive.write(file, arcPath);
					}
					fileToSend = parent + "\\" + PathFindFileNameA(filePath.c_str()) + ".zip";
					archive.save(fileToSend);
				}
				else {
					// 普通文件直接发送
					fileToSend = filePath;
				}
				// 初始化 UDP 广播
				WSAData wsaData;
				if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
					auto sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
					if (SOCKET_ERROR != sendSocket) {
						bool broadcast = true;
						setsockopt(sendSocket, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));
						SOCKADDR_IN receiverAddr{};
						receiverAddr.sin_family = AF_INET;
						receiverAddr.sin_port = htons(udpPort);
						receiverAddr.sin_addr.S_un.S_addr = htonl(INADDR_BROADCAST);
						/*
						*  数据包(32-1024B)
						*  | --------------------- | --------------- | --------------------- |
						*  |        标识头(16B)        |      Payload      |       标识尾(16B)         |
						*  | --------------------- | --------------- | --------------------- |
						*  |   Pigeon 2021/9/19  |       0-988B      |  91/9/1202 noegiP   |
						*  | --------------------- | --------------- | --------------------- |
						*
						*  Payload
						*  | -------------------- | ------------------------------ | ----------------------- | --------------- | ----------------- |
						*  |      包类型(1B)          |             文件类型(1B)               |       文件名(260B)          |    MD5(32B)     |      包数量(4B)     |
						*  | -------------------- | ------------------------------ | ----------------------- | --------------- | ----------------- |
						*  |      0x01 文件头       |      0x01 单文件  0x02 目录      |        xxx xxxx xxx\0     |        摘要          |  unsigned long    |
						*  | -------------------- | ------------------------------ | ----------------------- | --------------- | ----------------- |
						*  (298B)
						*
						*  | -------------------- | --------------- | ------------------ | ------------------- |
						*  |      包类型(1B)          |    MD5(32B)     |       包序号(4B)      |     数据(0-512B)      |
						*  | -------------------- | --------------- | ------------------ | ------------------- |
						*  |      0x02 数据块        |        摘要         |     unsigned long   |      0101010....       |
						*  | -------------------- | --------------- | ------------------ | ------------------- |
						*  (37-549B)
						*
						*  请求重传
						*  ...
						*/
						auto hFile = CreateFileA(
							fileToSend.c_str(),
							GENERIC_READ,
							FILE_SHARE_READ,
							NULL,
							OPEN_EXISTING,
							FILE_FLAG_SEQUENTIAL_SCAN,
							NULL);
						if (hFile != INVALID_HANDLE_VALUE) {
							// 获取文件信息
							auto fileSize = GetFileSize(hFile, NULL);
							auto fileName = PathFindFileNameA(fileToSend.c_str());
							auto fileMd5 = getFileMd5(fileToSend);
							// 初始化发送缓存
							char sendBuf[1024] = { 0 };
							int bufLength;
							auto packageHead = "Pigeon 2021/9/19";
							auto packageTail = "91/9/1202 noegiP";
							memset(sendBuf, 0, sizeof(sendBuf));
							memcpy(sendBuf, packageHead, 16);
							bufLength = 16;
							// 发送文件头
							memset(sendBuf + bufLength, 0x01, 1);
							bufLength += 1;
							memset(sendBuf + bufLength, fileAttr & FILE_ATTRIBUTE_DIRECTORY ? 0x02 : 0x01, 1);
							bufLength += 1;
							memcpy(sendBuf + bufLength, fileName, strlen(fileName));
							bufLength += 260;
							memcpy(sendBuf + bufLength, fileMd5.data(), fileMd5.size());
							bufLength += (int)fileMd5.size();
							DWORD packageAmount = fileSize / 512 + (fileSize % 512 == 0 ? 0 : 1);
							memcpy(sendBuf + bufLength, &packageAmount, sizeof(packageAmount));
							bufLength += sizeof(packageAmount);
							memcpy(sendBuf + bufLength, packageTail, 16);
							bufLength += 16;
							sendto(sendSocket, sendBuf, bufLength, 0, (SOCKADDR*)&receiverAddr, sizeof(receiverAddr));
							// 读文件
							BYTE readBuf[512] = { 0 };
							DWORD cbRead = 0;
							DWORD packageIndex = 1;
							while (ReadFile(hFile, readBuf, sizeof(readBuf), &cbRead, NULL)) {
								if (cbRead == 0) break;
								memset(sendBuf, 0, sizeof(sendBuf));
								memcpy(sendBuf, packageHead, 16);
								bufLength = 16;
								// 构建并发送文件块
								memset(sendBuf + bufLength, 0x02, 1);
								bufLength += 1;
								memcpy(sendBuf + bufLength, fileMd5.data(), fileMd5.size());
								bufLength += (int)fileMd5.size();
								memcpy(sendBuf + bufLength, &packageIndex, sizeof(packageIndex));
								bufLength += sizeof(packageIndex);
								packageIndex++;
								memcpy(sendBuf + bufLength, readBuf, cbRead);
								bufLength += cbRead;
								memcpy(sendBuf + bufLength, packageTail, 16);
								bufLength += 16;
								sendto(sendSocket, sendBuf, bufLength, 0, (SOCKADDR*)&receiverAddr, sizeof(receiverAddr));
								printf("\r");
								std::cout << "发送数据包：" << std::fixed << std::setprecision(2) << (float)packageIndex*100/packageAmount << "%";
								// 30kBps
								//Sleep(1); 
							}
							CloseHandle(hFile);
							// 不工作
							/*if (fileAttr & FILE_ATTRIBUTE_DIRECTORY) {
								if (!DeleteFileA(fileToSend.c_str())) {
									char* msgBuf = NULL;
									FormatMessageA(
										FORMAT_MESSAGE_ALLOCATE_BUFFER |
										FORMAT_MESSAGE_FROM_SYSTEM |
										FORMAT_MESSAGE_IGNORE_INSERTS,
										NULL,
										GetLastError(),
										MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
										(LPTSTR)&msgBuf,
										0, NULL);
									std::cout << std::endl << std::string(msgBuf) << std::endl;
									system("pause");
								}
							}*/
						}
						closesocket(sendSocket);
					}
				}
			}
		}
	}
	else if (result.count("serve")) {
		// 以服务形式运行
		std::vector<fileInfo> recvFileInfo;
		std::vector<packInfo> recvPackInfo;
		// 初始化 UDP 广播接收
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
			auto recvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (SOCKET_ERROR != recvSocket) {
				bool broadcast = true;
				setsockopt(recvSocket, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));
				SOCKADDR_IN receiverAddr{};
				receiverAddr.sin_family = AF_INET;
				receiverAddr.sin_port = htons(udpPort);
				receiverAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
				auto ret = bind(recvSocket, (SOCKADDR*)&receiverAddr, sizeof(receiverAddr));
				if (ret == 0) {
					std::cout << "正在监听 " << udpPort << " 端口" << std::endl;
					char recvBuf[1024] = { 0 };
					SOCKADDR_IN senderAddr{};
					int senderAddrLength = sizeof(senderAddr);
					// 公共
					char fileMd5Buf[32] = { 0 };
					// 0x01 文件头
					char fileNameBuf[260] = { 0 };
					std::string fileName;
					DWORD packageAmount = 0;
					auto isDir = false;
					// 0x02 数据包
					DWORD packageIndex = 0;
					char dataBuf[512] = { 0 };
					// 头尾标识
					auto packageHead = "Pigeon 2021/9/19";
					auto packageTail = "91/9/1202 noegiP";
					// 缓存
					fileInfo* fInfo = NULL;
					packInfo* pInfo = NULL;
					while (1)
					{
						ret = recvfrom(recvSocket, recvBuf, sizeof(recvBuf), 0, (SOCKADDR*)&senderAddr, &senderAddrLength);
						if (ret > 32) {
							// 校验头尾
							if (memcmp(recvBuf, packageHead, 16) == 0 && memcmp(recvBuf + ret - 16, packageTail, 16) == 0) {
								int fileIndex = 0;
								switch (recvBuf[16])
								{
								case 0x01:
									memcpy(fileNameBuf, recvBuf + 16 + 2, sizeof(fileNameBuf));
									memcpy(fileMd5Buf, recvBuf + 16 + 262, sizeof(fileMd5Buf));
									memcpy(&packageAmount, recvBuf + 16 + 294, sizeof(packageAmount));
									fileName = std::string(fileNameBuf);
									isDir = recvBuf[16 + 1] ^ 0x01;
									fInfo = new fileInfo();
									memcpy(fInfo->md5, fileMd5Buf, sizeof(fInfo->md5));
									fInfo->name = fileName;
									fInfo->packCount = packageAmount;
									fInfo->isDir = isDir;
									recvFileInfo.push_back(*fInfo);
									std::cout << std::endl << "接收文件头：" << fileName << std::endl;
									break;
								case 0x02:
									memcpy(fileMd5Buf, recvBuf + 16 + 1, sizeof(fileMd5Buf));
									memcpy(&packageIndex, recvBuf + 16 + 33, sizeof(packageIndex));
									memcpy(dataBuf, recvBuf + 16 + 37, (size_t)ret - 32 - 37);
									pInfo = new packInfo();
									memcpy(pInfo->md5, fileMd5Buf, sizeof(pInfo->md5));
									pInfo->index = packageIndex;
									memcpy(pInfo->data, dataBuf, sizeof(dataBuf));
									pInfo->dataLength = ret - 32 - 37;
									recvPackInfo.push_back(*pInfo);
									printf("\r");
									std::cout << "接收数据包：" << packageIndex;
									for each (auto f in recvFileInfo)
									{
										if (strcmp(f.md5, pInfo->md5)) {
											if (f.packCount == pInfo->index) {
												std::cout << std::endl << "接收完毕" << std::endl;
												std::vector<char> fileContent;
												int expectIdx = 1;
												int scanPtr = 0;
												while (expectIdx <= f.packCount)
												{
													if (scanPtr >= recvPackInfo.size()) break;
													packInfo pack = recvPackInfo.at(scanPtr);
													if (strcmp(f.md5, pack.md5)) {
														if (pack.index != expectIdx) break;
														// 对应
														for (auto i = 0; i < pack.dataLength; i++) {
															fileContent.push_back(pack.data[i]);
														}
														expectIdx++;
														recvPackInfo.erase(recvPackInfo.begin() + scanPtr);
													}
													else scanPtr++;
												}
												if (expectIdx > f.packCount) recvFileInfo.erase(recvFileInfo.begin() + fileIndex);
												// 保存到桌面
												CHAR desktopPath[260];
												SHGetSpecialFolderPathA(NULL, desktopPath, CSIDL_DESKTOPDIRECTORY, 0);
												int fileNameOffset = 0;
												std::string fullFileName = std::string(desktopPath) + '\\' + f.name;
												while (GetFileAttributesA(fullFileName.c_str()) != INVALID_FILE_ATTRIBUTES) {
													fileNameOffset++;
													fullFileName = std::string(desktopPath) + '\\' +
														(fileNameOffset == 0 ? "" : ("(" + std::to_string(fileNameOffset) + ")")) + f.name;
												}
												auto hFile = CreateFileA(
													fullFileName.c_str(),
													GENERIC_READ | GENERIC_WRITE,
													FILE_SHARE_READ,
													NULL,
													CREATE_ALWAYS,
													FILE_ATTRIBUTE_NORMAL,
													NULL
												);
												if (hFile != INVALID_HANDLE_VALUE) {
													DWORD written;
													WriteFile(hFile, fileContent.data(), fileContent.size(), &written, NULL);
													if (written == fileContent.size()) {
														std::cout << "文件保存到：" << fullFileName << std::endl;
														auto newFileMd5 = getFileMd5(fullFileName);
														if (!strcmp(newFileMd5.data(), f.md5)) {
															DeleteFileA(fullFileName.c_str());
														}
														else {
															std::cout << "MD5 校验通过" << std::endl;
															// 不工作
															/*if (f.isDir) {
																miniz_cpp::zip_file archive(fullFileName);
																std::string desktopPathRefined(desktopPath);
																replaceAll(desktopPathRefined, "\\", "/");
																archive.extractall(desktopPathRefined);
															}*/
															MessageBoxA(GetForegroundWindow(), ("已保存至 " + fullFileName).c_str(), "收到文件", MB_OK);
														}
													}
													CloseHandle(hFile);
												}
												break;
											}
										}
										fileIndex++;
									}
									break;
								default:
									std::cout << "未知数据报" << std::endl;
									break;
								}
							}
						}
					}
				}
			}
		}
	}
	else if (result.count("uninstall")) {
		// 卸载程序
		// ...
	}
	else if (argc == 1) {
		// 安装程序
		if (!isElevated()) {
			// 获取管理员权限
			ShellExecuteA(NULL, "runas", argv[0], NULL, NULL, debug ? SW_NORMAL : SW_HIDE);
		}
		else {
			// 复制可执行文件
			CopyFileA(argv[0], installPath, false);
			addContentMenu("*");
			addContentMenu("Directory");
			startDaemon();
		}
	}
	return 0;
}

bool isElevated() {
	bool elevated = false;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION elevation{};
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
			elevated = elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return elevated;
}

void addContentMenu(const std::string& type) {
	HKEY contentMenu;
	if (ERROR_SUCCESS == RegCreateKeyA(
		HKEY_CLASSES_ROOT,
		(type + "\\shell\\Pigeon!\\command").c_str(),
		&contentMenu
	)) {
		// 点击右键菜单时，以发送参数启动
		std::string contentExec(installPath);
		contentExec += " -d -f \"%V\"";
		RegSetKeyValueA(contentMenu, NULL, NULL, REG_SZ, contentExec.c_str(), (DWORD)contentExec.length());
		RegCloseKey(contentMenu);
	}
	else {
		std::cout << "为" + type + "添加右键菜单失败" << std::endl;
	}
}

void startDaemon() {
	ShellExecuteA(NULL, "runas", installPath, "-s", NULL, debug ? SW_NORMAL : SW_HIDE);
}

std::vector<std::string> walkThrough(const std::string& path) {
	std::vector<std::string> files;
	WIN32_FIND_DATAA found;
	auto finder = FindFirstFileA((path + "\\*").c_str(), &found);
	while (finder != INVALID_HANDLE_VALUE)
	{
		std::string fileName(found.cFileName);
		if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (fileName != "." && fileName != "..") {
				auto res = walkThrough(path + '\\' + fileName);
				files.reserve(files.size() + res.size());
				files.insert(files.end(), res.begin(), res.end());
			}
		}
		else {
			files.push_back(path + '\\' + fileName);
		}
		if (FindNextFileA(finder, &found) == 0) break;
	}
	return files;
}

void replaceAll(std::string& str, const std::string& from, const std::string& to) {
	if (from.empty()) return;
	size_t start = 0;
	while ((start = str.find(from, start)) != std::string::npos) {
		str.replace(start, from.length(), to);
		start += to.length();
	}
}

std::string getFileMd5(const std::string& filePath) {
	auto hFile = CreateFileA(
		filePath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);
	auto rainbow = "0123456789ABCDEF";
	std::string MD5 = "";
	if (hFile != INVALID_HANDLE_VALUE) {
		HCRYPTPROV hProv = 0;
		if (CryptAcquireContextA(
			&hProv,
			NULL,
			NULL,
			PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT)) {
			HCRYPTHASH hHash = 0;
			if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
				BYTE readBuf[1024] = { 0 };
				DWORD cbRead = 0;
				while (ReadFile(hFile, readBuf, sizeof(readBuf), &cbRead, NULL)) {
					if (cbRead == 0) break;
					CryptHashData(hHash, readBuf, cbRead, 0);
				}
				DWORD cbHash = 16; //  MD5LEN
				BYTE hashVal[16] = { 0 };
				if (CryptGetHashParam(hHash, HP_HASHVAL, hashVal, &cbHash, 0)) {
					for (unsigned char i = 0; i < cbHash; i++) {
						MD5 += rainbow[hashVal[i] >> 4];
						MD5 += rainbow[hashVal[i] & 0xf];
					}
				}
			}
		}
	}
	return MD5;
}
