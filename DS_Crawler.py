import argparse
import requests
import struct


class ParsingError(Exception): pass


class DataBlock(object):

    def __init__(self, data, debug=False):
        super(DataBlock, self).__init__()
        self.data = data
        self.pos = 0
        self.debug = debug

    def offset_read(self, length, offset=None):
        if not offset:
            offset_position = self.pos
        else:
            offset_position = offset

        if len(self.data) < offset_position + length:
            raise ParsingError('Offset+Length > len(self.data)')

        if not offset:
            self.pos += length

        value = self.data[offset_position:offset_position + length]
        self._log('Reading: {}-{} => {}'.format(hex(offset_position), hex(offset_position + length), value))
        return value

    def skip(self, length):
        self.pos += length

    def read_filename(self):
        length, = struct.unpack_from('>I', self.offset_read(4))
        filename = self.offset_read(2 * length).decode('utf-16be')
        structure_id, = struct.unpack_from('>I', self.offset_read(4))
        structure_type, = struct.unpack_from('>4s', self.offset_read(4))

        structure_type = structure_type.decode()
        self._log('Structure type ', structure_type)
        skip = -1
        while skip < 0:
            if structure_type == 'bool':
                skip = 1
            elif structure_type == 'type' or structure_type == 'long' or structure_type == 'shor' or structure_type == 'fwsw' or structure_type == 'fwvh' or structure_type == 'icvt' or structure_type == 'lsvt' or structure_type == 'vSrn' or structure_type == 'vstl':
                skip = 4
            elif structure_type == 'comp' or structure_type == 'dutc' or structure_type == 'icgo' or structure_type == 'icsp' or structure_type == 'logS' or structure_type == 'lg1S' or structure_type == 'lssp' or structure_type == 'modD' or structure_type == 'moDD' or structure_type == 'phyS' or structure_type == 'ph1S':
                skip = 8
            elif structure_type == 'blob':
                blen, = struct.unpack_from('>I', self.offset_read(4))
                skip = blen
            elif structure_type == 'ustr' or structure_type == 'cmmt' or structure_type == 'extn' or structure_type == 'GRP0':
                blen, = struct.unpack_from('>I', self.offset_read(4))
                skip = 2 * blen
            elif structure_type == 'BKGD':
                skip = 12
            elif structure_type == 'ICVO' or structure_type == 'LSVO' or structure_type == 'dscl':
                skip = 1
            elif structure_type == 'Iloc' or structure_type == 'fwi0':
                skip = 16
            elif structure_type == 'dilc':
                skip = 32
            elif structure_type == 'lsvo':
                skip = 76
            elif structure_type == 'icvo':
                pass
            elif structure_type == 'info':
                pass
            else:
                pass

            if skip <= 0:
                self._log('Re-reading!')
                self.skip(-1 * 2 * 0x4)
                filename += self.offset_read(0x2).decode('utf-16be')
                structure_id, = struct.unpack_from('>I', self.offset_read(4))
                structure_type, = struct.unpack_from('>4s', self.offset_read(4))
                structure_type = structure_type.decode()
                future_structure_type = struct.unpack_from('>4s', self.offset_read(4, offset=self.pos))
                self._log('Re-read structure_id {} / structure_type {}'.format(structure_id, structure_type))
                if structure_type != 'blob' and future_structure_type != 'blob':
                    structure_type = ''
                    self._log('Forcing another round!')

        self.skip(skip)
        self._log('Filename {}'.format(filename))
        return filename

    def _log(self, *args):
        if self.debug:
            print('[DEBUG] {}'.format(*args))


class DS_Store(DataBlock, object):

    def __init__(self, data, debug=False):
        super(DS_Store, self).__init__(data, debug)
        self.data = data
        self.root = self.__read_header()
        self.offsets = self.__read_offsets()
        self.toc = self.__read_TOC()
        self.freeList = self.__read_freelist()
        self.debug = debug

    def __read_header(self):

        if len(self.data) < 36:
            raise ParsingError('Length of data is too short!')

        magic1, magic2 = struct.unpack_from('>II', self.offset_read(2 * 4))
        if not magic1 == 0x1 and not magic2 == 0x42756431:
            raise ParsingError('Magic byte 1 does not match!')

        offset, size, offset2 = struct.unpack_from('>III', self.offset_read(3 * 4))
        self._log('Offset 1: {}'.format(offset))
        self._log('Size: {}'.format(size))
        self._log('Offset 2: {}'.format(offset2))
        if not offset == offset2:
            raise ParsingError('Offsets do not match!')
        self.skip(4 * 4)

        return DataBlock(self.offset_read(size, offset + 4), debug=self.debug)

    def __read_offsets(self):
        start_pos = self.root.pos
        count, = struct.unpack_from('>I', self.root.offset_read(4))
        self._log('Offset count: {}'.format(count))
        self.root.skip(4)

        offsets = []
        for i in range(count):
            address, = struct.unpack_from('>I', self.root.offset_read(4))
            self._log('Offset {} is {}'.format(i, address))
            if address == 0:
                continue
            offsets.append(address)

        section_end = start_pos + (count // 256 + 1) * 256 * 4 - count * 4

        self.root.skip(section_end)
        self._log('Skipped {} to {}'.format(hex(self.root.pos + section_end), hex(self.root.pos)))
        self._log('Offsets: {}'.format(offsets))
        return offsets

    def __read_TOC(self):
        self._log('POS {}'.format(hex(self.root.pos)))
        count, = struct.unpack_from('>I', self.root.offset_read(4))
        self._log('Toc count: {}'.format(count))
        toc = {}
        for i in range(count):
            toc_len, = struct.unpack_from('>b', self.root.offset_read(1))
            toc_name, = struct.unpack_from('>{}s'.format(toc_len), self.root.offset_read(toc_len))
            block_id, = struct.unpack_from('>I', self.root.offset_read(4))
            toc[toc_name.decode()] = block_id

        self._log('Toc {}'.format(toc))
        return toc

    def __read_freelist(self):
        freelist = {}
        for i in range(32):
            freelist[2 ** i] = []
            blkcount, = struct.unpack_from('>I', self.root.offset_read(4))
            for j in range(blkcount):
                free_offset, = struct.unpack_from('>I', self.root.offset_read(4))
                freelist[2 ** i].append(free_offset)

        self._log('Freelist: {}'.format(freelist))
        return freelist

    def __block_by_id(self, block_id):
        if len(self.offsets) < block_id:
            raise ParsingError('BlockID out of range!')

        addr = self.offsets[block_id]

        offset = (int(addr) >> 0x5 << 0x5)
        size = 1 << (int(addr) & 0x1f)
        self._log('New block: addr {} offset {} size {}'.format(addr, offset + 0x4, size))
        return DataBlock(self.offset_read(size, offset + 0x4), debug=self.debug)

    def traverse_root(self):
        root = self.__block_by_id(self.toc['DSDB'])
        root_id, = struct.unpack('>I', root.offset_read(4))
        self._log('Root-ID ', root_id)
        internal_block_count, = struct.unpack('>I', root.offset_read(4))
        record_count, = struct.unpack('>I', root.offset_read(4))
        block_count, = struct.unpack('>I', root.offset_read(4))
        unknown, = struct.unpack('>I', root.offset_read(4))

        return self.traverse(root_id)

    def traverse(self, block_id):
        node = self.__block_by_id(block_id)
        next_pointer, = struct.unpack('>I', node.offset_read(4))
        count, = struct.unpack('>I', node.offset_read(4))
        self._log('Next Ptr {} with {} '.format(hex(next_pointer), hex(count)))

        filenames = []
        if next_pointer > 0:
            for i in range(0, count, 1):
                next_id, = struct.unpack('>I', node.offset_read(4))
                self._log('Child: {}'.format(next_id))
                files = self.traverse(next_id)
                filenames += files
                filename = node.read_filename()
                self._log('Filename: ', filename)
                filenames.append(filename)
            files = self.traverse(next_pointer)
            filenames += files
        else:
            for i in range(0, count, 1):
                f = node.read_filename()
                filenames.append(f)

        return filenames


class Crawler:
    def __init__(self, target, debug=False):
        self.target = target
        self.debug = debug
        self._log('Crawling started')

    def crawl(self, target=False):
        if not target:
            target = self.target
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:60.0) Gecko/20100101 Firefox/60.0'}
        self._log('Crawling ' + target)
        r = requests.get(target + '/.DS_Store', headers=headers)
        if r.status_code == 200:
            ds = DS_Store(r.content, self.debug)
            files = ds.traverse_root()
            for file in list(set(files)):
                self.crawl(target + '/' + file)
                print('\033[92m' + '[+]' + '\033[m' + ' Found ' + target + '/' + file)

    def _log(self, *args):
        if self.debug:
            print('\033[93m' + '[DEBUG]'+'\033[m'+' {}'.format(*args))

def banner():
    print('\033[92m\033[1m'+'''    ___  __     ___                   _           
   /   \/ _\   / __\ __ __ ___      _| | ___ _ __ 
  / /\ /\ \   / / | '__/ _` \ \ /\ / / |/ _ \ '__|
 / /_// _\ \ / /__| | | (_| |\ V  V /| |  __/ |   
/___,'  \__/ \____/_|  \__,_| \_/\_/ |_|\___|_|   
                        '''+'\033[91m'+'''v1.0 [0xdeadbeef]'''+'\033[m')
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='web site that you want to crawl')
    parser.add_argument('-v', '--verbose', help='To enable verbosity', action='store_true')
    args = parser.parse_args()
    target = args.url
    verbose = args.verbose
    crawler = Crawler(target, verbose)
    crawler.crawl()


if __name__ == '__main__':
    banner()
    main()
