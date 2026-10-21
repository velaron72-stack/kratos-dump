#include "kratos/unwind.h"

namespace kratos {

namespace {

struct Cur {
  const u8* p;
  const u8* e;
  bool ok = true;
  Cur(const u8* b, const u8* end) : p(b), e(end) {}
  size_t left() const { return (size_t)(e - p); }
  u8 u8_() {
    if (p >= e) { ok = false; return 0; }
    return *p++;
  }
  u16 u16_(bool le) {
    if (left() < 2) { ok = false; p = e; return 0; }
    u16 v = rd16(p, le);
    p += 2;
    return v;
  }
  u32 u32_(bool le) {
    if (left() < 4) { ok = false; p = e; return 0; }
    u32 v = rd32(p, le);
    p += 4;
    return v;
  }
  u64 u64_(bool le) {
    if (left() < 8) { ok = false; p = e; return 0; }
    u64 v = rd64(p, le);
    p += 8;
    return v;
  }
  u64 uleb() {
    u64 v = 0;
    int sh = 0;
    for (;;) {
      if (p >= e) { ok = false; return v; }
      u8 b = *p++;
      if (sh < 64) v |= (u64)(b & 0x7f) << sh;
      sh += 7;
      if (!(b & 0x80)) break;
      if (sh > 70) { ok = false; return v; }
    }
    return v;
  }
  i64 sleb() {
    i64 v = 0;
    int sh = 0;
    u8 b = 0;
    for (;;) {
      if (p >= e) { ok = false; return v; }
      b = *p++;
      if (sh < 64) v |= (i64)(b & 0x7f) << sh;
      sh += 7;
      if (!(b & 0x80)) break;
      if (sh > 70) { ok = false; return v; }
    }
    if (sh < 64 && (b & 0x40)) v |= -((i64)1 << sh);
    return v;
  }
};

// DW_EH_PE value reader. `field_va` is the virtual address of the first byte of the field.
bool read_encoded(Cur& c, u8 enc, bool le, bool is64, u64 field_va, u64 data_base, u64& out, bool apply = true) {
  if (enc == 0xff) return false;
  if (enc & 0x80) return false;  // indirect: not supported for code addresses
  i64 v = 0;
  switch (enc & 0x0f) {
    case 0x00: v = is64 ? (i64)c.u64_(le) : (i64)(i32)c.u32_(le); if (!is64) v = (i64)(u32)v; break;
    case 0x01: v = (i64)c.uleb(); break;
    case 0x02: v = (i64)c.u16_(le); break;
    case 0x03: v = (i64)c.u32_(le); break;
    case 0x04: v = (i64)c.u64_(le); break;
    case 0x09: v = c.sleb(); break;
    case 0x0a: v = (i64)(i16)c.u16_(le); break;
    case 0x0b: v = (i64)(i32)c.u32_(le); break;
    case 0x0c: v = (i64)c.u64_(le); break;
    default: return false;
  }
  if (!c.ok) return false;
  if (apply) {
    switch (enc & 0x70) {
      case 0x00: break;
      case 0x10: v += (i64)field_va; break;
      case 0x30: v += (i64)data_base; break;
      default: return false;  // textrel/funcrel/aligned are not used for FDE ranges
    }
  }
  out = (u64)v;
  return true;
}

struct Cie {
  u8 fde_enc = 0;
  bool has_z = false;
  bool valid = false;
};

void parse_eh_frame(RunContext& rc, LibContext& lc, const u8* data, size_t size, u64 base_va, u64 data_base, UnwindResult& ur) {
  const ElfModel& m = lc.elf;
  const bool le = m.le, is64 = m.is64;
  std::unordered_map<u64, Cie> cies;
  size_t pos = 0;
  u64 guard = 0;
  while (pos + 4 <= size) {
    if ((++guard & 0xfff) == 0 && rc.cancel->cancelled()) return;
    if (ur.funcs.size() >= syscap::kMaxObjects) {
      ur.partial = true;
      return;
    }
    size_t start = pos;
    u64 len = rd32(data + pos, le);
    size_t hdr = 4;
    if (len == 0) break;  // terminator
    if (len == 0xffffffffull) {
      if (pos + 12 > size) { ur.skipped_entries++; break; }
      len = rd64(data + pos + 4, le);
      hdr = 12;
    }
    if (len > size - pos - hdr) {
      ur.skipped_entries++;
      ur.partial = true;
      break;
    }
    size_t body = pos + hdr;
    size_t next = body + (size_t)len;
    if (len < 4) { ur.skipped_entries++; pos = next; continue; }
    u32 id = rd32(data + body, le);
    if (id == 0) {
      // CIE
      Cur c(data + body + 4, data + next);
      Cie ci;
      u8 version = c.u8_();
      std::string aug;
      while (c.ok) {
        u8 ch = c.u8_();
        if (!c.ok || ch == 0) break;
        aug.push_back((char)ch);
        if (aug.size() > 16) { c.ok = false; break; }
      }
      if (c.ok && (version == 1 || version == 3 || version == 4)) {
        if (version == 4) { c.u8_(); c.u8_(); }  // address size, segment size
        if (aug.find("eh") == 0) c.p = std::min(c.p + (is64 ? 8 : 4), c.e);
        c.uleb();  // code alignment
        c.sleb();  // data alignment
        if (version == 1) c.u8_(); else c.uleb();  // return address register
        ci.fde_enc = 0;
        if (!aug.empty() && aug[0] == 'z') {
          ci.has_z = true;
          u64 alen = c.uleb();
          const u8* aend = c.p + std::min<u64>(alen, c.left());
          for (size_t i = 1; i < aug.size() && c.ok && c.p < aend; i++) {
            char ch = aug[i];
            if (ch == 'R') ci.fde_enc = c.u8_();
            else if (ch == 'L') c.u8_();
            else if (ch == 'P') {
              u8 penc = c.u8_();
              u64 dummy;
              Cur tmp = c;
              if (!read_encoded(tmp, penc & 0x7f, le, is64, 0, 0, dummy, false)) break;
              c = tmp;
            } else if (ch == 'S' || ch == 'B') {
            } else break;
          }
        }
        ci.valid = c.ok;
      }
      if (ci.valid) ur.cie_count++;
      cies[start] = ci;
    } else {
      // FDE: id is the distance back from this field to the CIE
      u64 cie_off = (u64)(body) - (u64)id;
      auto it = cies.find(cie_off);
      if (it == cies.end() || !it->second.valid) {
        ur.skipped_entries++;
        pos = next;
        continue;
      }
      Cur c(data + body + 4, data + next);
      u64 pc_begin = 0, pc_range = 0;
      u64 field_va = base_va + (u64)(c.p - data);
      bool ok = read_encoded(c, it->second.fde_enc, le, is64, field_va, data_base, pc_begin);
      ok = ok && read_encoded(c, (u8)(it->second.fde_enc & 0x0f), le, is64, 0, 0, pc_range, false);
      if (!ok || pc_begin == 0) {
        ur.skipped_entries++;
      } else {
        ur.funcs.push_back({pc_begin, pc_range, true});
        ur.fde_count++;
      }
    }
    pos = next;
  }
}

}  // namespace

UnwindResult read_unwind_tables(RunContext& rc, LibContext& lc) {
  UnwindResult ur;
  const ElfModel& m = lc.elf;

  // ---- .eh_frame ----
  {
    u64 foff = 0, va = 0, size = 0, hdr_va = 0;
    bool have = false;
    const ElfSection* sec = m.section_by_name(".eh_frame");
    const ElfSection* hsec = m.section_by_name(".eh_frame_hdr");
    if (hsec) hdr_va = hsec->addr;
    if (sec && sec->has_file_data() && sec->size && !sec->synthetic) {
      foff = sec->offset;
      va = sec->addr;
      size = sec->size;
      have = true;
      ur.source = ".eh_frame section";
    }
    if (!hdr_va || !have) {
      for (auto& s : m.segs) {
        if (s.type != elf::PT_GNU_EH_FRAME) continue;
        if (!hdr_va) hdr_va = s.vaddr;
        if (!have) {
          u8 h[16];
          u64 hoff;
          if (!m.vaddr_to_off(s.vaddr, hoff) || !lc.src->read_exact(hoff, h, 12)) break;
          if (h[0] != 1) break;
          Cur c(h + 4, h + 12);
          u64 ptr = 0;
          if (!read_encoded(c, h[1], m.le, m.is64, s.vaddr + 4, s.vaddr, ptr)) break;
          const ElfSegment* seg = m.seg_for_vaddr(ptr);
          u64 eoff;
          if (!seg || !m.vaddr_to_off(ptr, eoff)) break;
          foff = eoff;
          va = ptr;
          size = seg->vaddr + seg->filesz - ptr;
          have = true;
          ur.source = "PT_GNU_EH_FRAME";
        }
        break;
      }
    }
    if (have && size > 0) {
      ur.eh_frame_found = true;
      u64 cap = std::min<u64>(size, 512ull << 20);
      if (cap < size) ur.partial = true;
      if (rc.mem->try_reserve(cap)) {
        std::vector<u8> buf((size_t)cap);
        size_t got = lc.src->read_at(foff, buf.data(), (size_t)cap);
        if (got < cap) {
          ur.partial = true;
          buf.resize(got);
        }
        parse_eh_frame(rc, lc, buf.data(), buf.size(), va, hdr_va, ur);
        rc.mem->release(cap);
      } else {
        ur.partial = true;
        rc.warn("unwind", "not enough memory budget to read .eh_frame");
      }
    }
  }

  // ---- ARM exception index ----
  if (m.arch == Arch::Arm) {
    u64 foff = 0, va = 0, size = 0;
    bool have = false;
    for (auto& s : m.secs)
      if (s.type == elf::SHT_ARM_EXIDX && s.has_file_data() && s.size && !s.synthetic) {
        foff = s.offset; va = s.addr; size = s.size; have = true;
        break;
      }
    if (!have)
      for (auto& s : m.segs)
        if (s.type == elf::PT_ARM_EXIDX && s.filesz) {
          foff = s.offset; va = s.vaddr; size = s.filesz; have = true;
          break;
        }
    if (have) {
      ur.exidx_found = true;
      if (ur.source.empty()) ur.source = ".ARM.exidx";
      else ur.source += " + .ARM.exidx";
      u64 n = size / 8;
      size_t before = ur.funcs.size();
      std::vector<u8> buf((size_t)std::min<u64>(size, 64u << 20));
      u64 pos = 0;
      std::vector<u64> starts;
      while (pos < n * 8) {
        if (rc.cancel->cancelled()) return ur;
        size_t want = (size_t)std::min<u64>(buf.size(), n * 8 - pos);
        want -= want % 8;
        if (want == 0) break;
        size_t got = lc.src->read_at(foff + pos, buf.data(), want);
        if (got < 8) { ur.partial = true; break; }
        for (size_t i = 0; i + 8 <= got; i += 8) {
          u32 w0 = rd32(buf.data() + i, m.le);
          if (w0 & 0x80000000u) { ur.skipped_entries++; continue; }
          i64 off31 = (i64)(i32)(w0 << 1) >> 1;  // sign-extend 31 bits
          u64 fn = (u64)((i64)(va + pos + i) + off31);
          ur.exidx_entries++;
          if (starts.size() < syscap::kMaxObjects) starts.push_back(fn);
        }
        pos += got - got % 8;
        if (got < want) { ur.partial = true; break; }
      }
      std::sort(starts.begin(), starts.end());
      starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
      for (size_t i = 0; i < starts.size(); i++) {
        UnwindFunc f;
        f.start = starts[i];
        f.size = i + 1 < starts.size() ? starts[i + 1] - starts[i] : 0;
        f.exact = false;
        ur.funcs.push_back(f);
      }
      (void)before;
    }
  }
  return ur;
}

}  // namespace kratos
