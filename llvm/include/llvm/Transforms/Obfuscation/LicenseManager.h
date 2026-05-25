//===- LicenseManager.h - OLLVM卡密校验系统 -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// 本文件定义OLLVM卡密校验系统，基于优化的ChaCha20加密和时间戳验证
// 每个混淆Pass执行前都需要校验卡密是否有效
//
//===----------------------------------------------------------------------===//

#ifndef OBFUSCATION_LICENSEMANAGER_H
#define OBFUSCATION_LICENSEMANAGER_H

#include <cstdint>
#include <string>

namespace llvm {

bool isLicenseValidated();
bool validateLicense(const std::string &licenseKey);
std::string generateLicenseKey(uint64_t timestamp);

} // namespace llvm

#endif
