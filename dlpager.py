#/bin/env python

from idautils import *
from idaapi import *
from ida_bytes import *
from ida_segment import *

PAGE_SIZE = 4096

# Tested version:
#   RX = text + rodata, 0600
#   RW = data + bss, 0200

def insert_bits(dst, src, len, off):
	return ((dst & ~(((1 << len) - 1) << off)) | (( src &((1 << len) - 1)) << off))

def extract_bits(val, len, off):
	return ((val >> off) & ((1 << len) - 1))

def tableidx_bits(dst, src, len, off):
	return ((dst & ~((1 << len) - 1)) | ((src >> off) & ((1 << len) - 1)))

N_CHUNKS = 2
DICT1_BITS = 10
DICT2_BITS = 14
LB_BITS = 8

class q6zip:
	def __init__(self):
		self.src = 0
		self.end = 0
		self.dst = 0
		self.dict1 = 0
		self.dict2 = 0
		self.input = 0
		self.output = 0
		self.hold = 0
		self.bits = 0
		self.last = -1
		self.eof = 0

	def test_bits(self, n):
		if self.bits < n:
			print("q6zip: read requested %d, available %d" % (n, self.bits))
			raise Exception("q6zip: fatal")

	def peek_bits(self, n):
		self.test_bits(n)
		return (self.hold & ((1 << n) - 1))

	def skip_bits(self, n):
		self.test_bits(n)
		self.bits -= n
		self.hold >>= n
		if self.bits < 32 and self.input < self.end:
			self.hold |= (ida_bytes.get_dword(self.input) << self.bits)
			self.bits += 32
			self.input += 4
		self.hold &= ((1 << self.bits) - 1)

	def read_bits(self, n):
		self.test_bits(n)
		val = self.peek_bits(n)
		self.skip_bits(n)
		return val

	def read_last(self):
		va = self.output + self.last * 4
		if va < self.dst:
			print("q6zip: look back out of page, attempt 0x%x, src 0x%x, dst 0x%x, input 0x%x, output 0x%x, bits %d, hold 0x%x" %
				(va, self.src, self.dst, self.input, self.output, self.bits, self.hold))
			raise Exception("q6zip: fatal")
		return ida_bytes.get_dword(va)

	def read_back(self):
		self.last = tableidx_bits(self.last, self.read_bits(LB_BITS), LB_BITS, 0)
		return self.read_last()

	def write(self, val):
		if self.output >= self.dst + PAGE_SIZE:
			print("q6zip: write out of page")
			raise Exception("q6zip: fatal")
		# print("q6zip: *0x%x = 0x%x" % (self.output, val))
		put_dword(self.output, val)
		self.output += 4

	def decode_NO_MATCH(self):
		val = self.read_bits(32)
		self.write(val)

	def decode_MATCH_DICT1(self):
		idx = self.read_bits(DICT1_BITS)
		val = ida_bytes.get_dword(self.dict1 + idx * 4)
		self.write(val)

	def decode_MATCH_DICT2(self):
		idx = self.read_bits(DICT2_BITS)
		val = ida_bytes.get_dword(self.dict2 + idx * 4)
		self.write(val)

	def decode_MATCH_4N_4x0_SQ0(self):
		old = self.read_back()
		msk = self.read_bits(16)
		val = insert_bits(old, msk, 16, 0)
		self.write(val)

	def decode_MATCH_4N_4x0_SQ1(self):
		old = self.read_last()
		msk = self.read_bits(16)
		val = insert_bits(old, msk, 16, 0)
		self.write(val)

	def decode_MATCH_5N_3x0_SQ0(self):
		old = self.read_back()
		msk = self.read_bits(12)
		val = insert_bits(old, msk, 12, 0)
		self.write(val)

	def decode_MATCH_5N_3x0_SQ1(self):
		old = self.read_last()
		msk = self.read_bits(12)
		val = insert_bits(old, msk, 12, 0)
		self.write(val)

	def decode_MATCH_6N_2x0_SQ0(self):
		old = self.read_back()
		msk = self.read_bits(8)
		val = insert_bits(old, msk, 8, 0)
		self.write(val)

	def decode_MATCH_6N_2x0_SQ1(self):
		old = self.read_last()
		msk = self.read_bits(8)
		val = insert_bits(old, msk, 8, 0)
		self.write(val)

	def decode_MATCH_6N_2x2_SQ0(self):
		old = self.read_back()
		msk = self.read_bits(8)
		val = insert_bits(old, msk, 8, 8)
		self.write(val)

	def decode_MATCH_6N_2x2_SQ1(self):
		old = self.read_last()
		msk = self.read_bits(8)
		val = insert_bits(old, msk, 8, 8)
		self.write(val)

	def decode_MATCH_6N_2x4_SQ0(self):
		old = self.read_back()
		msk = self.read_bits(8)
		val = insert_bits(old, msk, 8, 16)
		self.write(val)

	def decode_MATCH_6N_2x4_SQ1(self):
		msk = self.read_bits(8)
		if msk == 255:
			self.eof = 1
			print("q6zip: decompressed 0x%x-0x%x(-%d) => 0x%x-0x%x" % (self.src - 8, self.input, self.bits, self.dst, self.output))
			return
		old = self.read_last()
		val = insert_bits(old, msk, 8, 16)
		self.write(val)

	def decode_MATCH_8N_SQ0(self):
		val = self.read_back()
		self.write(val)

	def decode_MATCH_8N_SQ1(self):
		val = self.read_last()
		self.write(val)

	def uncompress(self, src, end, dst, dict1, dict2, hold, bits, last):
		self.src = self.input = src
		self.end = end
		self.dst = self.output = dst
		self.dict1 = dict1
		self.dict2 = dict2
		self.hold = hold
		self.bits = bits
		self.last = last
		while self.eof == 0:
			op = self.peek_bits(4)
			if op == 0b000 or op == 0b1000:
				# print("q6zip: 000, MATCH_6N_2x0_SQ0")
				self.skip_bits(3)
				self.decode_MATCH_6N_2x0_SQ0()
			elif op == 0b001 or op == 0b1001:
				# print("q6zip: 001, MATCH_8N_SQ0")
				self.skip_bits(3)
				self.decode_MATCH_8N_SQ0()
			elif op == 0b0010:
				# print("q6zip: 0010, MATCH_5N_3x0_SQ0")
				self.skip_bits(4)
				self.decode_MATCH_5N_3x0_SQ0()
			elif op == 0b1010:
				self.skip_bits(4)
				op = self.read_bits(2)
				if op == 3:
					# print("q6zip: 111010, MATCH_6N_2x2_SQ0")
					self.decode_MATCH_6N_2x2_SQ0()
				elif op == 2:
					# print("q6zip: 101010, MATCH_6N_2x4_SQ0")
					self.decode_MATCH_6N_2x4_SQ0()
				elif op == 0:
					# print("q6zip: 001010, MATCH_4N_4x0_SQ1")
					self.decode_MATCH_4N_4x0_SQ1()
				else:
					op = self.read_bits(1)
					if op == 1:
						# print("q6zip: 1011010, MATCH_6N_2x2_SQ1")
						self.decode_MATCH_6N_2x2_SQ1()
					else:
						# print("q6zip: 0011010, MATCH_6N_2x4_SQ1")
						self.decode_MATCH_6N_2x4_SQ1()
			elif op == 0b011 or op == 0b1011:
				# print("q6zip: 011, NO_MATCH")
				self.skip_bits(3)
				self.decode_NO_MATCH()
			elif op == 0b100 or op == 0b1100:
				# print("q6zip: 100, MATCH_DICT1")
				self.skip_bits(3)
				self.decode_MATCH_DICT1()
			elif op == 0b0101:
				# print("q6zip: 0101, MATCH_DICT2")
				self.skip_bits(4)
				self.decode_MATCH_DICT2()
			elif op == 0b1101:
				self.skip_bits(4)
				op = self.read_bits(1)
				if op == 1:
					# print("q6zip: 11101, MATCH_5N_3x0_SQ1")
					self.decode_MATCH_5N_3x0_SQ1()
				else:
					# print("q6zip: 01101, MATCH_4N_4x0_SQ0")
					self.decode_MATCH_4N_4x0_SQ0()
			elif op == 0b110 or op == 0b1110:
				# print("q6zip: 110, MATCH_6N_2x0_SQ1")
				self.skip_bits(3)
				self.decode_MATCH_6N_2x0_SQ1()
			elif op == 0b111 or op == 0b1111:
				# print("q6zip: 111, MATCH_8N_SQ1")
				self.skip_bits(3)
				self.decode_MATCH_8N_SQ1()
		return self.output - self.dst

def load_rx(start_za, end_za, start_va, end_va):
	print("DLPAGER: start_va_compressed_text = 0x%x" % (start_za))
	print("DLPAGER: end_va_compressed_text = 0x%x" % (end_za))
	print("DLPAGER: start_va_uncompressed_text = 0x%x" % (start_va))
	print("DLPAGER: end_va_uncompressed_text = 0x%x" % (end_va))
	nb = ida_bytes.get_word(start_za)
	size = nb * PAGE_SIZE
	ver = ida_bytes.get_word(start_za + 2)
	print("DLPAGER: RX blocks = %d" % (nb))
	print("DLPAGER: RX version = 0x%04x" % (ver))
	if end_va - start_va != size:
		return
	print("DLPAGER: Create segment 0x%x@0x%x" % (end_va - start_va, start_va))
	s = segment_t()
	s.start_ea = start_va
	s.end_ea = end_va
	s.perm = SEGPERM_READ | SEGPERM_EXEC
	ida_segment.add_segm_ex(s, "DLPAGER_RX", None, ADDSEG_QUIET)
	zero = "\x00" * (end_va - start_va)
	put_bytes(start_va, zero)
	dict = start_za + 4
	dict1 = dict
	dict2 = dict1 + (1 << DICT1_BITS) * 4
	index = dict2 + (1 << DICT2_BITS) * 4
	for i in range(0, nb):
		src = ida_bytes.get_dword(index + i * 4)
		if i < nb - 1:
			src_next = ida_bytes.get_dword(index + i * 4 + 4)
		else:
			src_next = end_za
		dst = start_va + i * PAGE_SIZE
		test = ida_bytes.get_qword(src)
		# NO_MATCH/MATCH_DICT1/MATCH_DICT2
		no_match = (test & 0b111) == 0b011
		match_dict1 = (test & 0b111) == 0b100
		match_dict2 = (test & 0b1111) == 0b0101
		if no_match or match_dict1 or match_dict2:
			print("DLPAGER: decompress 0x%lx => 0x%lx" % (src, dst))
			zip = q6zip()
			zip.uncompress(src + 8, src_next, dst, dict1, dict2, test, 64, -1)
		else:
			print("DLPAGER: decompress partial 0x%lx => 0x%lx" % (src, dst))
			# struct metadata {
			#   signed last_sequencial:10;
			#   unsigned bits_left:6;
			#   unsigned in_delta:10;
			#   signed out_delta_from_chunk_size:6;
			# };
			metadata_last = []
			metadata_bits = []
			metadata_in_delta = []
			metadata_out_delta = []
			for n in range(0, N_CHUNKS):
				val = ida_bytes.get_word(src + n * 4)
				metadata_bits.append(val >> 10)
				val = val & 0b1111111111
				if (val & 0b1000000000) != 0:
					val |= -1
				metadata_last.append(val)
				val = ida_bytes.get_word(src + n * 4 + 2)
				metadata_in_delta.append(val & 0b1111111111)
				val = val >> 10
				if (val & 0b100000) != 0:
					val |= -1
				metadata_out_delta.append(val)
				# print("DLPAGER: decompress partial: metadata[%d]: last_sequencial = %d" % (n, metadata_last[n]))
				# print("DLPAGER: decompress partial: metadata[%d]: bits_left = %d" % (n, metadata_bits[n]))
				# print("DLPAGER: decompress partial: metadata[%d]: in_delta = %d" % (n, metadata_in_delta[n]))
				# print("DLPAGER: decompress partial: metadata[%d]: out_delta_from_chunk_size = %d" % (n, metadata_out_delta[n]))
			src += 4 * N_CHUNKS
			last = -1
			bits = 32
			for n in range(0, N_CHUNKS + 1):
				hold = ida_bytes.get_dword(src)
				hold >>= (32 - bits)
				hold |= ida_bytes.get_dword(src + 4) << bits
				if n < N_CHUNKS:
					end = src + metadata_in_delta[n] * 4 + 4
				else:
					end = src_next
				print("DLPAGER: decompress partial #%d, 0x%x-0x%x => 0x%x" % (n, src, end, dst))
				zip = q6zip()
				zip.uncompress(src + 8, end, dst, dict1, dict2, hold, bits + 32, last)
				if n < N_CHUNKS:
					src += metadata_in_delta[n] * 4
					dst += metadata_out_delta[n] * 4
					if n > 0:
						dst += PAGE_SIZE / N_CHUNKS
					last = metadata_last[n]
					bits = metadata_bits[n]

def load_rw(start_za, end_za, start_va, end_va):
	print("DLPAGER: start_va_compressed_rw = 0x%x" % (start_za))
	print("DLPAGER: end_va_compressed_rw = 0x%x" % (end_za))
	print("DLPAGER: start_va_uncompressed_rw = 0x%x" % (start_va))
	print("DLPAGER: end_va_uncompressed_rw = 0x%x" % (end_va))
	nb = ida_bytes.get_word(start_za)
	size = nb * PAGE_SIZE
	ver = ida_bytes.get_word(start_za + 2)
	print("DLPAGER: RW blocks = %d" % (nb))
	print("DLPAGER: RW version = 0x%04x" % (ver))
	if end_va - start_va < size:
		return
	print("DLPAGER: Create segment 0x%x(RW = 0x%x)@0x%x" % (end_va - start_va, size, start_va))
	s = segment_t()
	s.start_ea = start_va
	s.end_ea = end_va
	s.perm = SEGPERM_READ | SEGPERM_WRITE
	ida_segment.add_segm_ex(s, "DLPAGER_RW", None, ADDSEG_QUIET)
	# TODO:

# Search for dlpager:
# expect:
#   start_va_uncompressed_text
#   end_va_uncompressed_text
#   start_va_compressed_text
#   end_va_compressed_text
#   start_va_uncompressed_rw
#   end_va_uncompressed_rw
#   start_va_compressed_rw
#   end_va_compressed_rw
# or expect:
#   start_va_compressed_text
#   end_va_compressed_text
#   start_va_compressed_rw
#   end_va_compressed_rw
#   start_va_uncompressed_text
#   end_va_uncompressed_text
#   start_va_uncompressed_rw
#   end_va_uncompressed_rw
def main():
	dlpager_addr = 0
	all_seg = []
	n = get_segm_qty()
	for i in range(0, n):
		s = getnseg(i)
		all_seg.append(s.start_ea)
	for i in range(0, n):
		s = getnseg(i)
		if (s.perm & SEGPERM_READ) == SEGPERM_READ and (s.perm & SEGPERM_EXEC) == 0:
			bgn = s.start_ea
			end = s.end_ea
			if end - bgn < 32:
				continue
			while bgn < end - 32:
				val1 = ida_bytes.get_dword(bgn)
				val2 = ida_bytes.get_dword(bgn + 4)
				if val1 == 0xD0000000 and val2 > 0xD0000000:
					dlpager_addr = bgn
					print("DLPAGER: Trying 0x%x" % (dlpager_addr))
					test = ida_bytes.get_dword(dlpager_addr + 8)
					if test > 0xD0000000:
						start_va_compressed_text = ida_bytes.get_dword(dlpager_addr - 16)
						end_va_compressed_text = ida_bytes.get_dword(dlpager_addr - 12)
						start_va_uncompressed_text = ida_bytes.get_dword(dlpager_addr)
						end_va_uncompressed_text = ida_bytes.get_dword(dlpager_addr + 4)
						start_va_compressed_rw = ida_bytes.get_dword(dlpager_addr - 8)
						end_va_compressed_rw = ida_bytes.get_dword(dlpager_addr - 4)
						start_va_uncompressed_rw = ida_bytes.get_dword(dlpager_addr + 8)
						end_va_uncompressed_rw = ida_bytes.get_dword(dlpager_addr + 12)
					else:
						start_va_compressed_text = ida_bytes.get_dword(dlpager_addr + 8)
						end_va_compressed_text = ida_bytes.get_dword(dlpager_addr + 12)
						start_va_uncompressed_text = ida_bytes.get_dword(dlpager_addr)
						end_va_uncompressed_text = ida_bytes.get_dword(dlpager_addr + 4)
						start_va_compressed_rw = ida_bytes.get_dword(dlpager_addr + 24)
						end_va_compressed_rw = ida_bytes.get_dword(dlpager_addr + 28)
						start_va_uncompressed_rw = ida_bytes.get_dword(dlpager_addr + 16)
						end_va_uncompressed_rw = ida_bytes.get_dword(dlpager_addr + 20)
					# should be compressed segment start address
					if start_va_compressed_text in all_seg and start_va_compressed_rw in all_seg:
						break
					else:
						dlpager_addr = 0
				bgn += 4
			if dlpager_addr != 0:
				break
	if dlpager_addr == 0:
		print("DLPAGER: metadata not found")
		return
	load_rx(start_va_compressed_text, end_va_compressed_text,
			start_va_uncompressed_text, end_va_uncompressed_text)
	load_rw(start_va_compressed_rw, end_va_compressed_rw,
			start_va_uncompressed_rw, end_va_uncompressed_rw)
	print("DLPAGER: Done")

if __name__ == '__main__':
	main()
