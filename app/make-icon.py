# Делает иконку приложения из assets/logo.png по сетке иконок macOS:
# скруглённый квадрат 824×824 на холсте 1024 с отступами и мягкой тенью —
# как у остальных приложений в Launchpad/Dock.
# Запуск: python3 app/make-icon.py  (нужен Pillow)  → app/Vafa.icns, windows/vafa.ico
import os, subprocess, tempfile
from PIL import Image, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = Image.open(os.path.join(ROOT, 'assets/logo.png')).convert('RGB')
src = src.crop((237, 125, 1017, 905))            # голова волка с замком, без надписи

S, box, rad = 1024, 824, 185
off = (S - box) // 2
art = src.resize((box, box), Image.LANCZOS)
mask = Image.new('L', (box, box), 0)
ImageDraw.Draw(mask).rounded_rectangle((0, 0, box - 1, box - 1), rad, fill=255)

icon = Image.new('RGBA', (S, S), (0, 0, 0, 0))
shadow = Image.new('L', (S, S), 0)
ImageDraw.Draw(shadow).rounded_rectangle((off, off + 12, off + box, off + box + 12), rad, fill=110)
icon.paste((0, 0, 0, 255), (0, 0), shadow.filter(ImageFilter.GaussianBlur(18)))
icon.paste(art, (off, off), mask)
# тонкая светлая кромка — чёрная иконка не теряется на тёмном фоне
edge = Image.new('RGBA', (box, box), (0, 0, 0, 0))
ImageDraw.Draw(edge).rounded_rectangle((1, 1, box - 2, box - 2), rad, outline=(255, 255, 255, 40), width=3)
icon.alpha_composite(edge, (off, off))
icon.save(os.path.join(ROOT, 'assets/icon-1024.png'))

# macOS .icns
with tempfile.TemporaryDirectory() as t:
    iset = os.path.join(t, 'Vafa.iconset')
    os.mkdir(iset)
    for s in (16, 32, 128, 256, 512):
        icon.resize((s, s), Image.LANCZOS).save(f'{iset}/icon_{s}x{s}.png')
        icon.resize((s * 2, s * 2), Image.LANCZOS).save(f'{iset}/icon_{s}x{s}@2x.png')
    subprocess.run(['iconutil', '-c', 'icns', iset, '-o', os.path.join(ROOT, 'app/Vafa.icns')], check=True)

# Windows .ico — там иконки квадратные без отступов, берём скруглённый квадрат вплотную
win = Image.new('RGBA', (box, box), (0, 0, 0, 0))
win.paste(art, (0, 0), mask)
win.save(os.path.join(ROOT, 'windows/vafa.ico'),
         sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

# превью на фоне как в Launchpad
bg = Image.new('RGBA', (560, 300), (18, 40, 90, 255))
for x, y, s in ((20, 22, 256), (310, 86, 128), (470, 118, 64)):
    bg.alpha_composite(icon.resize((s, s), Image.LANCZOS), (x, y))
bg.save(os.path.join(tempfile.gettempdir(), 'vafa-icon-preview.png'))
print('готово, превью:', os.path.join(tempfile.gettempdir(), 'vafa-icon-preview.png'))
