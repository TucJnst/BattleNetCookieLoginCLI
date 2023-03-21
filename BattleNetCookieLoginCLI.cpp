#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>

#pragma comment(lib,"Crypt32.lib")

int OverwriteValues(HKEY hKey, LPCWSTR subKey, BYTE* pbData, DWORD cbData)
{
    DWORD dwDisposition;
    HKEY hSubKey;

    LONG lResult = RegCreateKeyExW(hKey, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hSubKey, &dwDisposition);
    if (lResult != ERROR_SUCCESS) {
        std::cerr << "Failed to create/open registry key: " << lResult << std::endl;
        return 0;
    }

    DWORD dwIndex = 0;
    WCHAR szValueName[MAX_PATH];
    DWORD dwValueNameLength = MAX_PATH;
    DWORD dwType;
    BYTE* lpData = NULL;
    DWORD dwDataSize = 0;
    while (RegEnumValueW(hSubKey, dwIndex++, szValueName, &dwValueNameLength, NULL, &dwType, NULL, &dwDataSize) == ERROR_SUCCESS) {
        lpData = new BYTE[dwDataSize];
        if (RegQueryValueExW(hSubKey, szValueName, NULL, &dwType, lpData, &dwDataSize) == ERROR_SUCCESS) {
            if (dwType == REG_BINARY) {
                // Modification de la valeur binaire
                lResult = RegSetValueExW(hSubKey, szValueName, 0, REG_BINARY, pbData, cbData);
                if (lResult != ERROR_SUCCESS) {
                    std::cerr << "Failed to overwrite registry value: " << lResult << std::endl;
                }
            }
        }
        delete[] lpData;
        lpData = NULL;
        dwValueNameLength = MAX_PATH;
        dwDataSize = 0;
    }

    RegCloseKey(hSubKey);
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <Cookie>" << std::endl;
        return 1;
    }

    std::string inputCookie = argv[1];

    BYTE entropyBytes[] = { 0xc8, 0x76, 0xf4, 0xae, 0x4c, 0x95, 0x2e, 0xfe, 0xf2, 0xfa, 0xf, 0x54, 0x19, 0xc0, 0x9c, 0x43 };

    BYTE* cookieBytes = (BYTE*) inputCookie.c_str();

    DATA_BLOB in;
    in.pbData = cookieBytes;
    in.cbData = inputCookie.size();
    DATA_BLOB entropy;
    entropy.pbData = entropyBytes;
    entropy.cbData = 16;
    DATA_BLOB out;

    CryptProtectData(&in, NULL, &entropy, NULL, NULL, 1, &out);

    if (OverwriteValues(HKEY_CURRENT_USER, L"SOFTWARE\\Blizzard Entertainment\\Battle.net\\UnifiedAuth", out.pbData, out.cbData) > 0)
    {
        std::cout << "Success!" << std::endl;
    }
    else
    {
        std::cout << "Couldn't find any reg values, are you sure that you are logged in with \"Keep logged in\" option?" << std::endl;
    }

    std::cout << out.pbData << std::endl;

    return 0;
}
