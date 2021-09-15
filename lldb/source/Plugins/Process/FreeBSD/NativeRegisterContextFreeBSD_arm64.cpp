//===-- NativeRegisterContextFreeBSD_arm64.cpp ----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#if defined(__aarch64__)

#include "NativeRegisterContextFreeBSD_arm64.h"

#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

#include "Plugins/Process/FreeBSD/NativeProcessFreeBSD.h"
#include "Plugins/Process/POSIX/ProcessPOSIXLog.h"
#include "Plugins/Process/Utility/RegisterInfoPOSIX_arm64.h"

// clang-format off
#include <sys/elf.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
// clang-format on

#define REG_CONTEXT_SIZE (GetGPRSize() + GetFPRSize())

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_freebsd;

NativeRegisterContextFreeBSD *
NativeRegisterContextFreeBSD::CreateHostNativeRegisterContextFreeBSD(
    const ArchSpec &target_arch, NativeThreadProtocol &native_thread) {
  Flags opt_regsets;
  opt_regsets.Set(RegisterInfoPOSIX_arm64::eRegsetMaskPAuth);
  auto register_info_up =
      std::make_unique<RegisterInfoPOSIX_arm64>(target_arch, opt_regsets);
  return new NativeRegisterContextFreeBSD_arm64(target_arch, native_thread,
      std::move(register_info_up));
}

NativeRegisterContextFreeBSD_arm64::NativeRegisterContextFreeBSD_arm64(
    const ArchSpec &target_arch, NativeThreadProtocol &native_thread,
    std::unique_ptr<RegisterInfoPOSIX_arm64> register_info_up)
    : NativeRegisterContextRegisterInfo(native_thread,
                                        register_info_up.release())
#ifdef LLDB_HAS_FREEBSD_WATCHPOINT
      ,
      m_read_dbreg(false)
#endif
{
  ::memset(&m_hwp_regs, 0, sizeof(m_hwp_regs));
  ::memset(&m_hbp_regs, 0, sizeof(m_hbp_regs));
  ::memset(&m_addr_mask, 0, sizeof(m_addr_mask));

  m_addr_mask_is_valid = false;
}

RegisterInfoPOSIX_arm64 &
NativeRegisterContextFreeBSD_arm64::GetRegisterInfo() const {
  return static_cast<RegisterInfoPOSIX_arm64 &>(*m_register_info_interface_up);
}

uint32_t NativeRegisterContextFreeBSD_arm64::GetRegisterSetCount() const {
  return GetRegisterInfo().GetRegisterSetCount();
}

const RegisterSet *
NativeRegisterContextFreeBSD_arm64::GetRegisterSet(uint32_t set_index) const {
  return GetRegisterInfo().GetRegisterSet(set_index);
}

uint32_t NativeRegisterContextFreeBSD_arm64::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < GetRegisterSetCount(); ++set_index)
    count += GetRegisterSet(set_index)->num_registers;
  return count;
}

bool NativeRegisterContextFreeBSD_arm64::IsGPR(unsigned reg) const {
  if (GetRegisterInfo().GetRegisterSetFromRegisterIndex(reg) ==
      RegisterInfoPOSIX_arm64::GPRegSet)
    return true;
  return false;
}

bool NativeRegisterContextFreeBSD_arm64::IsFPR(unsigned reg) const {
  if (GetRegisterInfo().GetRegisterSetFromRegisterIndex(reg) ==
      RegisterInfoPOSIX_arm64::FPRegSet)
    return true;
  return false;
}

bool NativeRegisterContextFreeBSD_arm64::IsAddrMask(unsigned reg) const {
  // Reuse the Linux PAuth mask register for now. On FreeBSD it can be
  // used when PAC isn't available, e.g. with TBI.
  return GetRegisterInfo().IsPAuthReg(reg);
}


Status NativeRegisterContextFreeBSD_arm64::ReadGPR() {
  return NativeProcessFreeBSD::PtraceWrapper(
      PT_GETREGS, m_thread.GetID(), m_reg_data.data());
}

Status NativeRegisterContextFreeBSD_arm64::WriteGPR() {
  return NativeProcessFreeBSD::PtraceWrapper(
      PT_SETREGS, m_thread.GetID(), m_reg_data.data());
}

Status NativeRegisterContextFreeBSD_arm64::ReadFPR() {
  return NativeProcessFreeBSD::PtraceWrapper(
      PT_GETFPREGS, m_thread.GetID(), m_fpreg_data.data());
}

Status NativeRegisterContextFreeBSD_arm64::WriteFPR() {
  return NativeProcessFreeBSD::PtraceWrapper(
      PT_SETFPREGS, m_thread.GetID(), m_fpreg_data.data());
}

Status NativeRegisterContextFreeBSD_arm64::ReadAddrMask() {
  Status error;

#ifdef NT_ARM_ADDR_MASK
  if (m_addr_mask_is_valid)
    return error;

  struct iovec ioVec;
  ioVec.iov_base = GetAddrMaskBuffer();
  ioVec.iov_len = GetAddrMaskBufferSize();

  error = NativeProcessFreeBSD::PtraceWrapper(
      PT_GETREGSET, m_thread.GetID(), &ioVec, NT_ARM_ADDR_MASK);

  if (error.Success())
    m_addr_mask_is_valid = true;
#endif

  return error;
}

uint32_t NativeRegisterContextFreeBSD_arm64::CalculateFprOffset(
    const RegisterInfo *reg_info) const {
  return reg_info->byte_offset - GetGPRSize();
}

uint32_t NativeRegisterContextFreeBSD_arm64::CalculateAddrMaskOffset(
    const RegisterInfo *reg_info) const {
  return reg_info->byte_offset - GetRegisterInfo().GetPAuthOffset();
}

Status
NativeRegisterContextFreeBSD_arm64::ReadRegister(const RegisterInfo *reg_info,
                                                 RegisterValue &reg_value) {
  Status error;

  if (!reg_info) {
    error.SetErrorString("reg_info NULL");
    return error;
  }

  const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];

  if (reg == LLDB_INVALID_REGNUM)
    return Status("no lldb regnum for %s", reg_info && reg_info->name
                                               ? reg_info->name
                                               : "<unknown register>");

  uint8_t *src;
  uint32_t offset = LLDB_INVALID_INDEX32;

  if (IsGPR(reg)) {
    error = ReadGPR();
    if (error.Fail())
      return error;

    offset = reg_info->byte_offset;
    assert(offset < GetGPRSize());
    src = (uint8_t *)GetGPRBuffer() + offset;
  } else if (IsFPR(reg)) {
    error = ReadFPR();
    if (error.Fail())
      return error;

    offset = CalculateFprOffset(reg_info);
    assert(offset < GetFPRSize());
    src = (uint8_t *)GetFPRBuffer() + offset;
  } else if (IsAddrMask(reg)) {
    error = ReadAddrMask();
    if (error.Fail())
      return error;

    offset = CalculateAddrMaskOffset(reg_info);
    assert(offset < GetAddrMaskBufferSize());
    src = (uint8_t *)GetAddrMaskBuffer() + offset;
  } else
    return Status("Failed to read register value");

  reg_value.SetFromMemoryData(reg_info, src, reg_info->byte_size,
                              endian::InlHostByteOrder(), error);
  return error;
}

Status NativeRegisterContextFreeBSD_arm64::WriteRegister(
    const RegisterInfo *reg_info, const RegisterValue &reg_value) {
  Status error;

  if (!reg_info)
    return Status("reg_info NULL");

  const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];

  if (reg == LLDB_INVALID_REGNUM)
    return Status("no lldb regnum for %s", reg_info && reg_info->name
                                               ? reg_info->name
                                               : "<unknown register>");

  uint8_t *dst;
  uint32_t offset = LLDB_INVALID_INDEX32;

  if (IsGPR(reg)) {
    error = ReadGPR();
    if (error.Fail())
      return error;

    assert(reg_info->byte_offset < GetGPRSize());
    dst = (uint8_t *)GetGPRBuffer() + reg_info->byte_offset;
    ::memcpy(dst, reg_value.GetBytes(), reg_info->byte_size);

    return WriteGPR();
  } else if (IsFPR(reg)) {
    error = ReadFPR();
    if (error.Fail())
      return error;

    offset = CalculateFprOffset(reg_info);
    assert(offset < GetFPRSize());
    dst = (uint8_t *)GetFPRBuffer() + offset;
    ::memcpy(dst, reg_value.GetBytes(), reg_info->byte_size);

    return WriteFPR();
  }

  return Status("Failed to write register value");
}

Status NativeRegisterContextFreeBSD_arm64::ReadAllRegisterValues(
    lldb::DataBufferSP &data_sp) {
  Status error;

  data_sp.reset(new DataBufferHeap(REG_CONTEXT_SIZE, 0));

  error = ReadGPR();
  if (error.Fail())
    return error;

  error = ReadFPR();
  if (error.Fail())
    return error;

  uint8_t *dst = data_sp->GetBytes();
  ::memcpy(dst, GetGPRBuffer(), GetGPRSize());
  dst += GetGPRSize();
  ::memcpy(dst, GetFPRBuffer(), GetFPRSize());

  return error;
}

Status NativeRegisterContextFreeBSD_arm64::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  Status error;

  if (!data_sp) {
    error.SetErrorStringWithFormat(
        "NativeRegisterContextFreeBSD_arm64::%s invalid data_sp provided",
        __FUNCTION__);
    return error;
  }

  if (data_sp->GetByteSize() != REG_CONTEXT_SIZE) {
    error.SetErrorStringWithFormat(
        "NativeRegisterContextFreeBSD_arm64::%s data_sp contained mismatched "
        "data size, expected %" PRIu64 ", actual %" PRIu64,
        __FUNCTION__, m_reg_data.size(), data_sp->GetByteSize());
    return error;
  }

  uint8_t *src = data_sp->GetBytes();
  if (src == nullptr) {
    error.SetErrorStringWithFormat("NativeRegisterContextFreeBSD_arm64::%s "
                                   "DataBuffer::GetBytes() returned a null "
                                   "pointer",
                                   __FUNCTION__);
    return error;
  }
  ::memcpy(GetGPRBuffer(), src, GetRegisterInfoInterface().GetGPRSize());

  error = WriteGPR();
  if (error.Fail())
    return error;

  src += GetRegisterInfoInterface().GetGPRSize();
  ::memcpy(GetFPRBuffer(), src, GetFPRSize());

  error = WriteFPR();
  if (error.Fail())
    return error;

  return error;
}

llvm::Error NativeRegisterContextFreeBSD_arm64::CopyHardwareWatchpointsFrom(
    NativeRegisterContextFreeBSD &source) {
#ifdef LLDB_HAS_FREEBSD_WATCHPOINT
  auto &r_source = static_cast<NativeRegisterContextFreeBSD_arm64 &>(source);
  llvm::Error error = r_source.ReadHardwareDebugInfo();
  if (error)
    return error;

  m_dbreg = r_source.m_dbreg;
  m_hbp_regs = r_source.m_hbp_regs;
  m_hwp_regs = r_source.m_hwp_regs;
  m_max_hbp_supported = r_source.m_max_hbp_supported;
  m_max_hwp_supported = r_source.m_max_hwp_supported;
  m_read_dbreg = true;

  // on FreeBSD this writes both breakpoints and watchpoints
  return WriteHardwareDebugRegs(eDREGTypeWATCH);
#else
  return llvm::Error::success();
#endif
}

llvm::Error NativeRegisterContextFreeBSD_arm64::ReadHardwareDebugInfo() {
#ifdef LLDB_HAS_FREEBSD_WATCHPOINT
  Log *log = GetLog(POSIXLog::Registers);

  // we're fully stateful, so no need to reread control registers ever
  if (m_read_dbreg)
    return llvm::Error::success();

  Status res = NativeProcessFreeBSD::PtraceWrapper(PT_GETDBREGS,
                                                   m_thread.GetID(), &m_dbreg);
  if (res.Fail())
    return res.ToError();

  LLDB_LOG(log, "m_dbreg read: debug_ver={0}, nbkpts={1}, nwtpts={2}",
           m_dbreg.db_debug_ver, m_dbreg.db_nbkpts, m_dbreg.db_nwtpts);
  m_max_hbp_supported = m_dbreg.db_nbkpts;
  m_max_hwp_supported = m_dbreg.db_nwtpts;
  assert(m_max_hbp_supported <= m_hbp_regs.size());
  assert(m_max_hwp_supported <= m_hwp_regs.size());

  m_read_dbreg = true;
  return llvm::Error::success();
#else
  return llvm::createStringError(
      llvm::inconvertibleErrorCode(),
      "Hardware breakpoints/watchpoints require FreeBSD 14.0");
#endif
}

llvm::Error
NativeRegisterContextFreeBSD_arm64::WriteHardwareDebugRegs(DREGType) {
#ifdef LLDB_HAS_FREEBSD_WATCHPOINT
  assert(m_read_dbreg && "dbregs must be read before writing them back");

  // copy data from m_*_regs to m_dbreg before writing it back
  for (uint32_t i = 0; i < m_max_hbp_supported; i++) {
    m_dbreg.db_breakregs[i].dbr_addr = m_hbp_regs[i].address;
    m_dbreg.db_breakregs[i].dbr_ctrl = m_hbp_regs[i].control;
  }
  for (uint32_t i = 0; i < m_max_hwp_supported; i++) {
    m_dbreg.db_watchregs[i].dbw_addr = m_hwp_regs[i].address;
    m_dbreg.db_watchregs[i].dbw_ctrl = m_hwp_regs[i].control;
  }

  return NativeProcessFreeBSD::PtraceWrapper(PT_SETDBREGS, m_thread.GetID(),
                                             &m_dbreg)
      .ToError();
#else
  return llvm::createStringError(
      llvm::inconvertibleErrorCode(),
      "Hardware breakpoints/watchpoints require FreeBSD 14.0");
#endif
}

#endif // defined (__aarch64__)
