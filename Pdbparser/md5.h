#pragma once

// swprintf
#pragma warning (disable : 4996)

#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <string>

std::string Md5(PVOID buffer, ULONG bufferLen);