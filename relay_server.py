"""
Natixa-chat Relay Sunucusu
==========================
Bu sunucu iki Natixa-chat kullanicisini bir "oda kodu" ile eslestirir ve
aralarinda gecen HER veriyi (yazi, dosya, sesli arama) korlemesine (blind)
birbirine iletir. Sunucu bu veriyi ASLA acmaz/okumaz/saklamaz - Natixa-chat
zaten her seyi kendi X25519 + AES-256-GCM sifrelemesiyle uctan uca sifreliyor
(bkz. crypto_session.py), sunucu sadece zaten sifreli olan bu paketleri bir
kapidan alip diger kapiya birebir yolluyor. Yani bu sunucuyu calistiran kisi
bile (hosting saglayicisi dahil) mesaj/ses icerigini goremez.

Bu sayede:
  - Port yonlendirme / UPnP / NAT-PMP / statik IP / CGNAT sorunu ORTADAN
    KALKAR: iki taraf da sadece bu sunucuya GIDEN (outbound) bir baglanti
    acar, kimse disaridan erisilebilir bir port acmak zorunda degildir.
  - Sunucu tamamen "kor bir boru" (dumb pipe) gibi calisir.

PROTOKOL
--------
Oda kodu TEK KULLANIMLIK degildir - iki tarafin surekli birbirini bulabildigi
KALICI bir eslesme kimligidir (Natixa-chat'in eski "son bagli IP'ye otomatik
yeniden baglan" ozelligiyle ayni mantik, sadece IP yerine kod kullanilir).

  Client -> Sunucu : {"action": "create"}
      -> Sunucu yeni, bos bir kod uretir.
  Sunucu -> Client : {"action": "created", "code": "AB3F9K"}

  Client -> Sunucu : {"action": "join", "code": "AB3F9K"}
      -> Bu kodla DAHA ONCE de baglanilmis olabilir (reconnect), sorun degil.
  Sunucu -> Client : {"action": "waiting"}          (oda hala tek kisilik)
                   ya da
  Sunucu -> Client (HER IKI tarafa da) : {"action": "paired"}   (oda 2 kisi oldu)
  Sunucu -> Client (kod bulunamadi/dolu) : {"action": "error", "message": "..."}

Eslesme tamamlandiktan sonra gelen HER binary (bytes) frame, gonderenin
karsi tarafina oldugu gibi iletilir. Sunucu bu frame'lerin icerigine hic
bakmaz.

Bir taraf koptugunda, diger tarafa {"action": "peer_left"} gonderilir ama oda
SILINMEZ - taraflardan biri ayni kodla tekrar "join" yaptiginda oda otomatik
olarak yeniden eslesir (bkz. yukaridaki "paired" akisi).

DEPLOY (Render.com ucretsiz katman)
------------------------------------
1. Bu dosyayi ve requirements.txt'i bir GitHub reposuna koy.
2. Render.com'da "New +" -> "Web Service" -> reponu sec.
3. Build command: pip install -r requirements.txt
   Start command: python relay_server.py
4. Render PORT ortam degiskenini otomatik saglar, kod zaten onu okuyor.
5. Deploy bitince sana verdigi adres (orn. https://natixa-relay.onrender.com)
   -> Natixa-chat ayarlarinda "wss://natixa-relay.onrender.com" olarak gir.

NOT: Render'in ucretsiz katmani bir sure istek gelmeyince "uyku" moduna gecer;
ilk baglantida birkac saniye "uyanma" gecikmesi olabilir, bu normaldir.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import string
import logging

import websockets
from websockets.server import WebSocketServerProtocol

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("relay")

CODE_CHARS = string.ascii_uppercase.replace("O", "").replace("I", "") + "23456789"
CODE_LENGTH = 6
ROOM_TIMEOUT_SECONDS = 600  # host odayi acip kimse katilmazsa 10 dk sonra oda silinir

# code -> {"members": set[ws] (en fazla 2), "created_at": float, "known": bool}
# "known": bu kod gercekten "create" ile uretildi mi, yoksa biri rastgele bir
# kod mu denedi - "join" sadece "known" odalara izin verir.
_rooms: dict[str, dict] = {}
# ws -> code : bu soketin hangi odaya ait oldugunu hizlica bulmak icin
_ws_room: dict[WebSocketServerProtocol, str] = {}


def _generate_code() -> str:
    while True:
        code = "".join(random.choices(CODE_CHARS, k=CODE_LENGTH))
        if code not in _rooms:
            return code


async def _cleanup_stale_rooms():
    """Uzun sure hic kimsenin (ne host ne guest) bagli olmadigi odalari
    periyodik olarak temizler - boylece kod alani sisip durmaz."""
    while True:
        await asyncio.sleep(60)
        now = asyncio.get_event_loop().time()
        stale = [
            code for code, room in _rooms.items()
            if not room["members"] and now - room["last_empty_at"] > ROOM_TIMEOUT_SECONDS
        ]
        for code in stale:
            del _rooms[code]
        if stale:
            log.info("Temizlenen bos odalar: %s", stale)


async def _send_json(ws: WebSocketServerProtocol, data: dict):
    try:
        await ws.send(json.dumps(data))
    except Exception:
        pass


async def _handle_create(ws: WebSocketServerProtocol):
    code = _generate_code()
    now = asyncio.get_event_loop().time()
    # Odayi olusturan taraf ayni zamanda odanin ilk uyesi olur - aksi halde
    # sadece kod uretilir ama kimse odada olmaz, karsi taraf join olunca da
    # oda hep "1 kisilik" kalir ve hicbir zaman eslesme (paired) tetiklenmez.
    _rooms[code] = {"members": {ws}, "known": True, "last_empty_at": now}
    _ws_room[ws] = code
    log.info("Oda olusturuldu: %s", code)
    await _send_json(ws, {"action": "created", "code": code})


async def _handle_join(ws: WebSocketServerProtocol, code: str):
    code = (code or "").strip().upper()
    room = _rooms.get(code)
    if room is None or not room.get("known"):
        await _send_json(ws, {"action": "error", "message": "Kod bulunamadi. Kodu kontrol et."})
        return
    if len(room["members"]) >= 2 and ws not in room["members"]:
        await _send_json(ws, {"action": "error", "message": "Bu odada zaten 2 kisi bagli."})
        return

    room["members"].add(ws)
    _ws_room[ws] = code

    if len(room["members"]) == 2:
        log.info("Oda eslesti (reconnect dahil): %s", code)
        for member in room["members"]:
            await _send_json(member, {"action": "paired"})
    else:
        await _send_json(ws, {"action": "waiting"})


async def _relay_target(ws: WebSocketServerProtocol):
    code = _ws_room.get(ws)
    if code is None:
        return None
    room = _rooms.get(code)
    if room is None:
        return None
    others = room["members"] - {ws}
    return next(iter(others), None)


async def _handle_disconnect(ws: WebSocketServerProtocol):
    code = _ws_room.pop(ws, None)
    if code is None:
        return
    room = _rooms.get(code)
    if room is None:
        return
    room["members"].discard(ws)
    for remaining in room["members"]:
        await _send_json(remaining, {"action": "peer_left"})
    if not room["members"]:
        room["last_empty_at"] = asyncio.get_event_loop().time()


async def handler(ws: WebSocketServerProtocol):
    peer_info = getattr(ws, "remote_address", ("?", 0))
    log.info("Yeni baglanti: %s", peer_info)
    try:
        async for message in ws:
            if isinstance(message, (bytes, bytearray)):
                # Eslesme tamamlanmis binary veri - korlemesine karsi tarafa ilet.
                target = await _relay_target(ws)
                if target is not None:
                    try:
                        await target.send(message)
                    except Exception:
                        pass
                continue

            # Kontrol mesaji (JSON metin)
            try:
                data = json.loads(message)
            except (json.JSONDecodeError, TypeError):
                continue

            action = data.get("action")
            if action == "create":
                await _handle_create(ws)
            elif action == "join":
                await _handle_join(ws, data.get("code", ""))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        await _handle_disconnect(ws)
        log.info("Baglanti kapandi: %s", peer_info)


async def health_check(path, request_headers):
    """Render (ve benzeri hosting'ler) '/' adresine duz HTTP GET ile saglik
    kontrolu yapar; bu bir WebSocket istegi degildir, o yuzden normal 200 OK
    donuyoruz. Gercek istemciler zaten /ws veya kok adrese WebSocket upgrade
    istegiyle baglanacagi icin bu, onlari etkilemez."""
    if "Upgrade" not in request_headers or request_headers.get("Upgrade", "").lower() != "websocket":
        return (200, [("Content-Type", "text/plain")], b"Natixa-chat relay ayakta.\n")
    return None


async def main():
    port = int(os.environ.get("PORT", 8765))
    asyncio.create_task(_cleanup_stale_rooms())
    log.info("Relay sunucusu %s portunda baslatiliyor...", port)
    async with websockets.serve(
        handler, "0.0.0.0", port,
        process_request=health_check,
        max_size=2 * 1024 * 1024,  # 2MB - fotograf/dosya parcalari icin yeterli
        ping_interval=20,
        ping_timeout=20,
    ):
        await asyncio.Future()  # sonsuza kadar calis


if __name__ == "__main__":
    asyncio.run(main())
