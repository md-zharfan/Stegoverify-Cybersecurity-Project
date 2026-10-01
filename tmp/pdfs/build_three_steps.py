from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Preformatted
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from pathlib import Path
out=Path('output/pdf/StegoVerify_Start_Location_Explained.pdf')
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='TitleX',fontName='Helvetica-Bold',fontSize=21,leading=25,textColor=colors.HexColor('#16324f'),spaceAfter=12))
styles.add(ParagraphStyle(name='Deck',fontSize=11,leading=16,textColor=colors.HexColor('#526477'),spaceAfter=12))
styles.add(ParagraphStyle(name='HeadX',fontName='Helvetica-Bold',fontSize=13,leading=17,textColor=colors.HexColor('#16324f'),spaceBefore=10,spaceAfter=6))
styles.add(ParagraphStyle(name='BodyX',fontSize=10,leading=13,spaceAfter=6))
styles.add(ParagraphStyle(name='CellX',fontSize=9,leading=12,spaceAfter=0))
styles.add(ParagraphStyle(name='CodeX',fontName='Courier',fontSize=9,leading=12,backColor=colors.HexColor('#f0f4f8'),borderPadding=10,spaceBefore=5,spaceAfter=10))
story=[]
def p(t,style='BodyX'): story.append(Paragraph(t,styles[style]))
def h(t): p(t,'HeadX')
def code(t): story.append(Preformatted(t,styles['CodeX']))
def table(rows,widths):
 t=Table([[Paragraph(c,styles['CellX']) for c in r] for r in rows],colWidths=widths,hAlign='LEFT')
 t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e4edf5')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6),('LINEBELOW',(0,0),(-1,-1),0.4,colors.HexColor('#d3dee8'))]))
 story.append(t); story.append(Spacer(1,10))
def footer(c,d):
 c.setFont('Helvetica',8); c.setFillColor(colors.HexColor('#66788a'))
 c.drawString(46,29,'StegoVerify | Three steps with exact code references')
 c.drawRightString(A4[0]-46,29,str(d.page))
import ast
out=Path('output/pdf/StegoVerify_Three_Steps_With_Code.pdf')
def ref(file,name):
 tree=ast.parse(Path(file).read_text(encoding='utf-8-sig'))
 for node in ast.walk(tree):
  if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name==name:
   return f'{file}:{node.lineno} ({name})'
 return file+' ('+name+')'
def sources(*items):
 p('<b>Code to open:</b> '+'; '.join(ref(*x) for x in items),'CellX')
def page(title,subtitle):
 if story: story.append(PageBreak())
 p(title,'TitleX');p(subtitle,'Deck')
def qa(q,a): p('<b>'+q+'</b><br/>'+a)
import textwrap
styles['CodeX'].fontSize=8.3
styles['CodeX'].leading=11
def snippet(file,a,b):
 p(f'<b>{file}, lines {a}-{b}</b>','CellX')
 lines=Path(file).read_text().splitlines(); result=[]
 for i in range(a,b+1):
  line=f'{i:3}  '+lines[i-1]
  result += textwrap.wrap(line,width=94,subsequent_indent='     ... ',replace_whitespace=False,drop_whitespace=False) or ['']
 code('\n'.join(result))
def bullet(t):p('- '+t)
page('Step 1  Make the masked cover hash','Shared secret used here? NO')
p('<b>There are two different hash-based results:</b> the masked cover hash is the media fingerprint; the HMAC result is calculated later using your secret. This guide follows the actual code, with line numbers and short speaking notes for each step.')
h('Function: ImageCover.masked_hash(n_lsb)')
snippet('stegoverify/covers.py',100,108)
bullet('<b>Line 101:</b> create a SHA-256 calculation.')
bullet('<b>Lines 102-103:</b> include an image label, dimensions and channel count.')
bullet('<b>Line 104:</b> get the embedding units, temporarily clear their lowest n bits, and feed those masked bytes into the hash.')
bullet('<b>Lines 105-107:</b> include unchanged alpha bytes if the image has transparency.')
bullet('<b>Line 108:</b> return the 32-byte fingerprint. No secret argument is read anywhere in this function.')
h('Helper: _mask_table(n_lsb)')
snippet('stegoverify/covers.py',37,39)
p('For n = 2, keep is binary <b>11111100</b>. AND with this mask clears the two lowest bits. translate() uses the lookup table to apply that rule to every unit. It does not modify the saved file.')
code('Original unit:  10110101 -> masked: 10110100\nStego unit:     10110110 -> masked: 10110100\nSame masked bytes -> same fingerprint.')
h('Where this is called')
snippet('stegoverify/payload.py',75,75)
p('This line is inside <b>payload.build_record()</b>, starting at line 71. The resulting fingerprint is saved as hexadecimal text in <b>record["hash"]</b> at line 99. For audio, the same method name selects <b>AudioCover.masked_hash()</b> at covers.py:183: it masks only the lowest byte of each channel sample and preserves higher bytes.')
p('<b>Say:</b> "First, we calculate the cover\'s masked fingerprint. The shared secret is not used in this step. We ignore the bits embedding changes so the sender and receiver can calculate the same fingerprint."')

page('Step 2  Calculate the HMAC result','Shared secret used here? YES, as the HMAC key')
h('Function: startloc.derive_start(...)')
snippet('stegoverify/startloc.py',42,46)
bullet('<b>Line 42:</b> receives five inputs: secret, cover type, masked fingerprint, LSB depth and number of units.')
bullet('<b>Lines 43-44:</b> reject an empty or missing secret.')
bullet('<b>Line 45:</b> join the fixed label, cover type, masked hash and n into a byte string called msg. This prepares the data; it does not yet calculate HMAC.')
bullet('<b>Line 46:</b> convert the secret text into UTF-8 bytes and pass it as the first argument, which is the HMAC key. Pass msg as the second argument, which is the data.')
h('Function: crypto_utils.hmac_sha256(key, msg)')
snippet('stegoverify/crypto_utils.py',98,99)
p('<b>cu</b> is the alias established by <b>from . import crypto_utils as cu</b> in startloc.py:36. The helper calls Python\'s standard-library hmac module; hashlib.sha256 selects the underlying hash algorithm. digest() returns 32 bytes, stored in mac on line 46.')
code('Key:  secret.encode("utf-8")\nData: fixed label + cover type + masked hash + n\n\nHMAC-SHA256(key, data) -> mac (32 bytes)')
table([['<b>Expression</b>','<b>Meaning</b>'],['b"SVFY-start|"','A public fixed byte-string label, not a password or salt.'],['cover_kind.encode()','The text image/audio converted to bytes.'],['masked_hash','The 32-byte fingerprint from Step 1.'],['bytes([n_lsb])','One byte storing the selected depth. n = 1 becomes 0x01, not the text character "1".'],['secret.encode("utf-8")','Your typed secret converted to key bytes. Encoding is not encryption.']],[176,327])
p('<b>What changes when you change only the secret?</b> Step 1\'s fingerprint stays the same for the same cover and n. The HMAC key changes, so its output is expected to change. The input data msg stays the same.')
p('<b>Say:</b> "Next, we use the shared secret as the HMAC key. The masked fingerprint, cover type and LSB depth are the data. HMAC-SHA256 produces a secret-dependent result; it does not encrypt or alter the cover fingerprint."')

page('Step 3  Convert the result into a position','The HMAC result becomes a valid start unit')
h('The return line in startloc.derive_start(...)')
snippet('stegoverify/startloc.py',47,47)
bullet('<b>int.from_bytes(mac, "big"):</b> interpret the 32 HMAC bytes as one large unsigned integer. Big means the first byte is most significant.')
bullet('<b>% num_units:</b> take the remainder after division by the cover\'s number of embedding units. The result is between 0 and N - 1, including zero.')
bullet('<b>return:</b> send that integer back to engine.protect(), which saves it in the variable start.')
code('Illustration only: 1,234 % 100 = 34\nSo, in a cover with 100 units, the start would be unit 34.')
h('Where the engine calls your function')
snippet('stegoverify/engine.py',116,121)
p('<b>Line 117:</b> record["hash"] is the Step 1 fingerprint stored as hex text. bytes.fromhex converts it back to its original 32 bytes. The other arguments come from the GUI settings and loaded cover. In manual mode, line 121 uses manual_unit directly; there is no HMAC call.')
h('Where the calculated position is used')
snippet('stegoverify/engine.py',125,128)
bullet('<b>Line 125:</b> obtain the stego copy\'s embedding units.')
bullet('<b>Line 126:</b> pass start to lsb.embed(). The hidden container starts at this unit; its header, record, signature and message move together.')
bullet('<b>Lines 127-128:</b> write the modified units back and save the output.')
p('In RGB images a unit is a colour-channel byte. In WAV audio a unit is the lowest byte of a channel sample. This is not a position in the compressed file bytes. lsb.embed() is in <b>lsb.py:110</b>; it replaces the selected low bits of consecutive units and wraps to zero if necessary.')
p('<b>Say:</b> "Finally, we convert the HMAC result into an integer and take it modulo the number of units. This gives a valid start position. The engine passes that number to the embedding function, which writes our whole container from there."')
p('<b>Important:</b> different HMAC outputs can produce the same remainder. Say a changed secret <i>usually</i> changes the start, not that it is guaranteed. The same inputs always reproduce the same start.')

page('Show the full connection in your demo','Receiver code, measured examples and a short explanation')
h('The GUI starts the chain')
p('The Protect button calls <b>App.p_run()</b> at app.py:457. It reads your secret using <b>self.p_secret.get()</b> and passes it to <b>engine.protect()</b> at app.py:479-481. The engine builds the record, derives the start and embeds the container.')
code('App.p_run()\n  -> engine.protect()\n     -> payload.build_record()\n        -> cover.masked_hash(n)              [Step 1]\n     -> startloc.derive_start(...)\n        -> crypto_utils.hmac_sha256(...)     [Step 2]\n        -> integer(mac) % num_units          [Step 3]\n     -> lsb.embed(..., start, n)')
h('The receiver repeats the same calculation')
snippet('stegoverify/engine.py',206,208)
p('This is inside <b>engine.verify()</b> at line 188. Here cover means the received stego file. The decoder computes its masked hash directly, then calls the same derive_start function. With the same secret, type, n and unit count, it gets the same start. Auto mode tries n = 1 to 8 if the depth is not supplied.')
p('<b>_locate()</b> at engine.py:170 checks for a valid SVFY header at that position, then optionally scans elsewhere. Signature and integrity checks follow. A genuine, intact container at a different position produces <b>Wrong Start Location</b> at engine.py:276-279.')
h('A real example you can point to')
p('Measured using the current <b>cover_image.png</b>, 512 x 384 RGB, at 1 LSB. Both runs use the same masked cover fingerprint.')
table([['<b>Shared secret</b>','<b>Masked hash</b>','<b>HMAC output prefix</b>','<b>Start unit</b>'],['team-secret-2026','Same','0dd2f4e6589d...','358,456'],['team-secret-2027','Same','30ffca770077...','141,331']],[142,83,164,114])
p('The first position is pixel (189, 233), G channel; the second is pixel (6, 92), G channel. These values were checked through the current engine, not invented. They depend on this exact sample and depth.')
h('Your explanation in four points')
bullet('"First, masked_hash makes a fingerprint of the cover without using the shared secret."')
bullet('"Second, hmac_sha256 uses that fingerprint and other settings as data, with my shared secret as the key."')
bullet('"Third, derive_start converts the HMAC output to an integer and applies modulo to get the starting unit."')
bullet('"The receiver repeats those steps. The masked fingerprint remains stable because embedding only changes the ignored bits."')
p('<b>Security limit:</b> the visible SVFY marker can be scanned for without the secret. The keyed location is not message encryption. AES-GCM separately protects message confidentiality.')
SimpleDocTemplate(str(out),pagesize=A4,rightMargin=46,leftMargin=46,topMargin=40,bottomMargin=46,title='StegoVerify Three Steps With Code',author='StegoVerify Team').build(story,onFirstPage=footer,onLaterPages=footer)
from pypdf import PdfReader
r=PdfReader(out);print('Pages:',len(r.pages))
for i,pg in enumerate(r.pages):print(i+1,len(pg.extract_text()))
