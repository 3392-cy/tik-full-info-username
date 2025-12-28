import requests
import json
import re
import time
import secrets
import random
import uuid
import ms4
from urllib.parse import urlencode
import SignerPy
import sys
from SignerPy import sign, get
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime

def slow_print(text, delay=0.05):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def slow_input(prompt, delay=0.08):
    for char in prompt:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    return input("")

slow_print("\nWelcome to TikTok Profile Insights by @gqpgqpg on tele\n")

class webaccountinfo:
    def __init__(self, username):
        self.username = username
        self.web_info = {}
        self.base()
        self.getwebinfo(
        self.gqpgqpg,
        self.system,
        self.profileTab,
        self.stats
    )

    def base(self):
        url = f"https://www.tiktok.com/@{self.username}"
        headers = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"}
        response = requests.get(url, headers=headers)
        match = re.search(r'({"__DEFAULT_SCOPE__":.*})</script>', response.text)
        if not match:
            print("Error: Could not find user data in page")
            return
        data = json.loads(match.group(1))
        self.gqpgqpg = data["__DEFAULT_SCOPE__"]["webapp.user-detail"]["userInfo"]
        self.system = {0: "Public", 1: "Friends", 2: "Private"}
        self.profileTab = self.gqpgqpg['user']['profileTab']
        self.stats = self.gqpgqpg['stats']
    #-------------by gqpgqpg -------------------------
    def getwebinfo(self, gqpgqpg, system, profileTab, stats):
        idd = gqpgqpg['user']['id']
        shortId = gqpgqpg['user']['shortId']
        uniqueId = gqpgqpg['user']['uniqueId']
        nickname = gqpgqpg['user']['nickname']
        avatar = gqpgqpg['user']['avatarLarger']
        signature = gqpgqpg['user']['signature']
        createTime = gqpgqpg['user']['createTime']
        created_date = datetime.datetime.fromtimestamp(createTime).strftime("%Y-%m-%d %H:%M:%S")
        verified = gqpgqpg['user']['verified']
        secUid = gqpgqpg['user']['secUid']
        ftc = gqpgqpg['user']['ftc']
        relation = gqpgqpg['user']['relation']
        if relation==0:
            relation="No Follow"
        elif relation==1:
            relation="You Follow Them"
        elif relation==2:
            relation="They Follow You"
        elif relation==3:
            relation="Mutual Follow"
        else:
            relation="N/A"
        fav = gqpgqpg['user']['openFavorite']
        commentSetting = gqpgqpg['user']['commentSetting']
        commentSettingStr = system[commentSetting]
        commerceUser = gqpgqpg['user']['commerceUserInfo']['commerceUser']
        duetSetting = gqpgqpg['user']['duetSetting']
        duetSettingStr = system[duetSetting]
        stitchSetting = gqpgqpg['user']['stitchSetting']
        stitchSettingStr = system[stitchSetting]
        privateAccount = gqpgqpg['user']['privateAccount']
        secret = gqpgqpg['user']['secret']
        isADVirtual = gqpgqpg['user']['isADVirtual']
        roomId = gqpgqpg['user']['roomId']
        uniqueIdModifyTime = gqpgqpg['user']['uniqueIdModifyTime']
        ttSeller = gqpgqpg['user']['ttSeller']
        downloadSetting = gqpgqpg['user']['downloadSetting']
        language = gqpgqpg['user']['language']
        eventlist = gqpgqpg['user']['eventList']
        recommendReason = gqpgqpg['user']['recommendReason']
        nowaccountcardurl = gqpgqpg['user']['nowInvitationCardUrl']
        nicknamemodifytime = gqpgqpg['user']['nickNameModifyTime']
        isEmbedBanned = gqpgqpg['user']['isEmbedBanned']
        canExpPlaylist = gqpgqpg['user']['canExpPlaylist']
        profileembedpermission = gqpgqpg['user']['profileEmbedPermission']
        followingVisibility = gqpgqpg['user']['followingVisibility']
        followingVisibilityStr = system[followingVisibility]
        if profileembedpermission == 0:
            profileembedpermissionStr = "Disabled"
        elif profileembedpermission == 1:
            profileembedpermissionStr = "Enabled"
        else:
            profileembedpermissionStr = "N/A"
        if downloadSetting == 0:
            downloadSettingStr = "Disabled"
        elif downloadSetting == 1:
            downloadSettingStr = "Allow video download"
        elif downloadSetting == 2:
            downloadSettingStr = "Allow video download"
        elif downloadSetting == 3:
            downloadSettingStr = "Allow video both vid/photo"
        else:
            downloadSettingStr = "N/A"
        isorganization = gqpgqpg['user']['isOrganization']
        if isorganization==1:
            isorganization="Yes"
        elif isorganization==0:
            isorganization="No"
        else:
            isorganization="N/A"
        userstorystatus = gqpgqpg['user']['UserStoryStatus']
        if userstorystatus == 0:
            userstorystatusStr = "No active story"
        elif userstorystatus == 1:
            userstorystatusStr = "Has active story"
        elif userstorystatus == 2: 
            userstorystatusStr = "Story expired"
        else:
            userstorystatusStr = "N/A"
        suggestaccountbind = gqpgqpg['user']['suggestAccountBind']
        musicTab = profileTab['showMusicTab']
        questionTab = profileTab['showQuestionTab']
        playlistTab = profileTab['showPlayListTab']
        followerCount=stats['followerCount']
        followingCount=stats['followingCount']
        heartCount=stats['heartCount']
        videoCount=stats['videoCount']
        diggCount=stats['diggCount']
        friendCount=stats['friendCount']

        self.web_info = {
    "id": idd,
    "shortId": shortId,
    "uniqueId": uniqueId,
    "nickname": nickname,
    "avatar": avatar,
    "bio": signature,
    "createTime": created_date,
    "verified": verified,
    "secUid": secUid,
    "ftc": ftc,
    "relation": relation,
    "Suggesgt acc bind":suggestaccountbind,
    "Event list":eventlist,
    "Recommand reason":recommendReason,
    "Card url":nowaccountcardurl,
    "Nichname modify time":datetime.datetime.fromtimestamp(nicknamemodifytime).strftime("%Y-%m-%d %H:%M:%S"),
    "Embed banned":isEmbedBanned,
    "Export playlist":canExpPlaylist,
    "Account settings": {
        "Favorite": fav,
        "Comment setting": commentSettingStr,
        "Duet setting": duetSettingStr,
        "Stitch setting": stitchSettingStr,
        "Private": privateAccount,
        "Secret": secret,
        "AD virtual": isADVirtual,
        "Room id": roomId,
        "Username last change": uniqueIdModifyTime,
        "Seller": ttSeller,
        "Download settings": downloadSettingStr,
        "Language": language,
        "Organization": isorganization,
        "Story status": userstorystatusStr,
        "Embed permission": profileembedpermissionStr,
        "Followings visibility": followingVisibilityStr,
        "Music tab": musicTab,
        "Question tab": questionTab,
        "Playlist tab": playlistTab,
        },
    "stats": {
        "followers": followerCount,
        "following": followingCount,
        "likes": heartCount,
        "videos": videoCount,
        "digg": diggCount,
        "friends": friendCount
    }
}

class accountsecuirtyinfo:
    def __init__(self, username):
        self.username = username
        self.security_info = {}
        self.getsecinfo()

    HOSTS = [
        "api16-normal-c-alisg.tiktokv.com",
        "api.tiktokv.com",
        "api-h2.tiktokv.com",
        "api-va.tiktokv.com",
        "api16.tiktokv.com",
        "api16-va.tiktokv.com",
        "api19.tiktokv.com",
        "api19-va.tiktokv.com",
        "api21.tiktokv.com",
        "api15-h2.tiktokv.com",
        "api21-h2.tiktokv.com",
        "api21-va.tiktokv.com",
        "api22.tiktokv.com",
        "api22-va.tiktokv.com",
        "api-t.tiktok.com",
        "api16-normal-baseline.tiktokv.com",
        "api23-normal-zr.tiktokv.com",
        "api21-normal.tiktokv.com",
        "api22-normal-zr.tiktokv.com",
        "api33-normal.tiktokv.com",
        "api22-normal.tiktokv.com",
        "api31-normal.tiktokv.com",
        "api15-normal.tiktokv.com",
        "api31-normal-cost-sg.tiktokv.com",
        "api3-normal.tiktokv.com",
        "api31-normal-zr.tiktokv.com",
        "api9-normal.tiktokv.com",
        "api16-normal.tiktokv.com",
        "api16-normal.ttapis.com",
        "api19-normal-zr.tiktokv.com",
        "api16-normal-zr.tiktokv.com",
        "api16-normal-apix.tiktokv.com",
        "api74-normal.tiktokv.com",
        "api32-normal-zr.tiktokv.com",
        "api23-normal.tiktokv.com",
        "api32-normal.tiktokv.com",
        "api16-normal-quic.tiktokv.com",
        "api-normal.tiktokv.com",
        "api16-normal-apix-quic.tiktokv.com",
        "api19-normal.tiktokv.com",
        "api31-normal-cost-mys.tiktokv.com",
        "im-va.tiktokv.com",
        "imapi-16.tiktokv.com",
        "imapi-16.musical.ly",
        "imapi-mu.isnssdk.com",
        "api.tiktok.com",
        "api.ttapis.com",
        "api.tiktokv.us",
        "api.tiktokv.eu",
        "api.tiktokw.us",
        "api.tiktokw.eu"
    ]

    @staticmethod
    def sendreq(host, username, attempt_num):
        try:
            secret = secrets.token_hex(16)
            cookies = {
                "passport_csrf_token": secret,
                "passport_csrf_token_default": secret
            }
            params_step1 = {
                'request_tag_from': "h5",
                'manifest_version_code': "410203",
                '_rticket': str(int(time.time() * 1000)),
                'app_language': "en",
                'app_type': "normal",
                'iid': str(random.randint(1, 10**19)),
                'app_package': "com.zhiliaoapp.musically.go",
                'channel': "googleplay",
                'device_type': "RMX3834",
                'language': "en",
                'host_abi': "arm64-v8a",
                'locale': "en",
                'resolution': "720*1454",
                'openudid': "b57299cf6a5bb211",
                'update_version_code': "410203",
                'ac2': "lte",
                'cdid': str(uuid.uuid4()),
                'sys_region': "US",
                'os_api': "34",
                'timezone_name': "America/New_York",
                'dpi': "272",
                'carrier_region': "US",
                'ac': "4g",
                'device_id': str(random.randint(1, 10**19)),
                'os': "android",
                'os_version': "14",
                'timezone_offset': "10800",
                'version_code': "410203",
                'app_name': "musically_go",
                'ab_version': "41.2.3",
                'version_name': "41.2.3",
                'device_brand': "realme",
                'op_region': "US",
                'ssmix': "a",
                'device_platform': "android",
                'build_number': "41.2.3",
                'region': "US",
                'aid': "1340",
                'ts': str(int(time.time())),
                'okhttp_version': "4.1.103.107-ul",
                'use_store_region_cookie': "1"
            }
            url1 = f"https://{host}/passport/find_account/tiktok_username/?" + urlencode(params_step1)
            payload1 = {'mix_mode': "1", 'username': username}
            signature = SignerPy.sign(params=url1, payload=payload1, version=4404)
            headers_step1 = {
                'User-Agent': "com.zhiliaoapp.musically.go/410203 (Linux; Android 14; en; RMX3834)",
                'x-ss-req-ticket': signature['x-ss-req-ticket'],
                'x-ss-stub': signature['x-ss-stub'],
                'x-gorgon': signature["x-gorgon"],
                'x-khronos': signature["x-khronos"],
                'x-tt-passport-csrf-token': cookies['passport_csrf_token'],
                'passport_csrf_token': cookies['passport_csrf_token'],
                'content-type': "application/x-www-form-urlencoded",
            }
            res1 = requests.post(url1, data=payload1, headers=headers_step1, cookies=cookies, timeout=15)
            respj1 = res1.json()
            if "token" in respj1.get("data", {}):
                token = respj1["data"]["token"]
                params_step2 = params_step1.copy()
                params_step2['not_login_ticket'] = token
                params_step2['ts'] = str(int(time.time()))
                params_step2['_rticket'] = str(int(time.time() * 1000))
                url2 = f"https://{host}/passport/auth/available_ways/?" + urlencode(params_step2)
                signature_step2 = SignerPy.sign(params=url2, payload=None, version=4404)
                headers_step2 = {
                    'User-Agent': "com.zhiliaoapp.musically.go/410203 (Linux; Android 14; en; RMX3834)",
                    'x-ss-req-ticket': signature_step2['x-ss-req-ticket'],
                    'x-ss-stub': signature_step2['x-ss-stub'],
                    'x-gorgon': signature_step2["x-gorgon"],
                    'x-khronos': signature_step2["x-khronos"],
                    'x-tt-passport-csrf-token': cookies['passport_csrf_token'],
                    'passport_csrf_token': cookies['passport_csrf_token'],
                    'content-type': "application/x-www-form-urlencoded",
                }
                res_step2 = requests.post(url2, headers=headers_step2, cookies=cookies, timeout=15)
                response_json_step2 = res_step2.json()
                if 'success' in response_json_step2.get("message", ""):
                    data = response_json_step2.get('data', {})
                    return {
                        'data': {
                            'has_email': data.get('has_email', False),
                            'has_mobile': data.get('has_mobile', False),
                            'has_passkey': data.get('has_passkey', False),
                            'oauth_platforms': data.get('oauth_platforms', [])
                        },
                        'message': 'success',
                        'host': host
                    }
            elif "verify_center_decision_conf" in res1.text:
                return {"message": "error", "status": "captcha", "host": host}
            else:
                return {"message": "error", "status": "user not found", "host": host}
        except Exception as e:
            return {"message": "error", "status": "request_failed", "host": host, "error": str(e)}
        return {"message": "error", "status": "unknown", "host": host}

    @staticmethod
    def sendthread(username, max_workers=10):
        successful_responses = []
        failed_hosts = []
        def worker(host):
            result = accountsecuirtyinfo.sendreq(host, username, 1)
            if result.get('message') == 'success':
                successful_responses.append(result)
            else:
                failed_hosts.append({'host': host, 'status': result.get('status', 'unknown')})
            return result
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(worker, host): host for host in accountsecuirtyinfo.HOSTS}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    future.result()
                except Exception as _:
                    failed_hosts.append({'host': host, 'status': 'thread_error'})
        if successful_responses:
            print(f"✅ Success on {len(successful_responses)} servers")
            return successful_responses[0]
        else:
            print(f"❌ All servers failed ({len(failed_hosts)} failures)")
            return {"message": "error", "status": "all hosts failed", "failed_count": len(failed_hosts)}

    def getsecinfo(self):
        response = self.sendthread(self.username, max_workers=10)
        self.security_info = response
        if response.get('message') == 'success':
            response_data = response.get('data', {})
            has_email = response_data.get('has_email', False)
            has_mobile = response_data.get('has_mobile', False)
            has_passkey = response_data.get('has_passkey', False)
            oauth_platforms = response_data.get('oauth_platforms', [])
            hidden_binding = "Hidden links available ⚠️" if has_passkey else "No hidden links ✅"
            external_binding = "External links available ⚠️" if oauth_platforms else "No external links ✅"
            phone_status = "✔️" if has_mobile else "❌"
            email_status = "✔️" if has_email else "❌"

            self.mess = {
            "Phone": phone_status,
            "Email": email_status,
            "Hidden Binding": hidden_binding,
            "External Binding": external_binding,
            "OAuth Platforms": oauth_platforms,
            "Passkey": has_passkey
        }
    
        else:
            status = response.get('status', 'unknown')
            if status == "captcha":
                print("Captcha error.")
            elif status == "user not found":
                print("User not found")
            elif status == "all hosts failed":
                print("All hosts failed")
            else:
                print("Error,")
        return self.mess

class appaccountinfo:
    def __init__(self, username, user_id):
        self.username = username
        self.user_id = user_id
        self.lvl = ""
        self.analytics_data = {}
        self.summ = {}  # store summary info
        self.level()
        self.analytics()
        self.country()  # populates self.summ

    def country(self):
        data = ms4.InfoTik.TikTok_Info(self.username)
        self.summ = {
            "country": data.get('country') or "N/A",  
            "flag": data.get('flag') or ""
        }
        return self.summ  # <-- important to return


    def level(self):
        url = "https://webcast22-normal-c-alisg.tiktokv.com/webcast/user/"

        headers = {
            "Host": "webcast22-normal-c-alisg.tiktokv.com",
            "cookie": "store-idc=alisg; passport_csrf_token=20e9da8b0e16abaa45d4ce2ad75a1325; passport_csrf_token_default=20e9da8b0e16abaa45d4ce2ad75a1325; d_ticket=913261767c3f16148c133796e661c1d83cf5d; multi_sids=7464926696447099909%3A686e699e8bbbc4e9f5e08d31c038c8e4; odin_tt=e2d5cd703c2e155d572ad323d28759943540088ddc6806aa9a9b48895713be4b585e78bf3eb17d28fd84247c4198ab58fab17488026468d3dde38335f4ab928ad1b9bd82a2fb5ff55da00e3368b4d215; cmpl_token=AgQQAPMsF-RPsLemUeAYPZ08_KeO5HxUv5IsYN75Vg; sid_guard=686e699e8bbbc4e9f5e08d31c038c8e4%7C1751310846%7C15552000%7CSat%2C+27-Dec-2025+19%3A14%3A06+GMT; uid_tt=683a0288ad058879bbc16d3b696fa815e1d72c050bdb2d14b824141806068417; uid_tt_ss=683a0288ad058879bbc16d3b696fa815e1d72c050bdb2d14b824141806068417; sid_tt=686e699e8bbbc4e9f5e08d31c038c8e4; sessionid=686e699e8bbbc4e9f5e08d31c038c8e4; sessionid_ss=686e699e8bbbc4e9f5e08d31c038c8e4; store-country-code=eg; store-country-code-src=uid; tt-target-idc=alisg; ttwid=1%7Cmdx9QyT3L35S3CFNpZ_6a1mG2Q3hbfWvwQh6gY5hjhw%7C1751310949%7C253ef523ddc8960c5f52b286d8ce0afc2623ec081a777dac3ba5606ecdc1bd40; store-country-sign=MEIEDPH3p6xlgJXYVovxBgQgMf22gnCf0op7iOSSy6oKKB7paF60OVLAsxbGkh6BUGAEEF0aMxzItZZ03IrkjedsuYY; msToken=Srtgt7p6ncYXI8gph0ecExfl9DpgLtzOynFNZjVGLkKUjqV0J1JI8aBoE8ERmO5f43HQhtJxcU2FeJweSbFIlIOADOHP_z75VvNeA2hp5LN1JZsKgj-wymAdEVJt",
            "x-tt-pba-enable": "1",
            "x-bd-kmsv": "0",
            "x-tt-dm-status": "login=1;ct=1;rt=1",
            "live-trace-tag": "profileDialog_batchRequest",
            "sdk-version": "2",
            "x-tt-token": "034865285659c6477b777dec3ab5cd0aa70363599c1acde0cd4e911a51fed831bdb2ec80a9a379e8e66493471e519ccf05287299287a55f0599a72988865752a3668a1a459177026096896cf8d50b6e8b5f4cec607bdcdee5a5ce407e70ce91d52933--0a4e0a20da4087f3b0e52a48822384ac63e937da36e5b0ca771f669a719cf633d66f8aed12206a38feb1f115b80781d5cead8068600b779eb2bba6c09d8ae1e6a7bc44b46b931801220674696b746f6b-3.0.0",
            "passport-sdk-version": "6031490",
            "x-vc-bdturing-sdk-version": "2.3.8.i18n",
            "x-tt-request-tag": "n=0;nr=011;bg=0",
            "x-tt-store-region": "eg",
            "x-tt-store-region-src": "uid",
            "rpc-persist-pyxis-policy-v-tnc": "1",
            "x-ss-dp": "1233",
            "x-tt-trace-id": "00-c24dca7d1066c617d7d3cb86105004d1-c24dca7d1066c617-01",
            "user-agent": "com.zhiliaoapp.musically/2023700010 (Linux; U; Android 11; vi; SM-A105F; Build/RP1A.200720.012; Cronet/TTNetVersion:f6248591 2024-09-11 QuicVersion:182d68c8 2024-05-28)",
            "accept-encoding": "gzip, deflate, br",
            "x-tt-dataflow-id": "671088640"
        }

        params = {
            "user_role": '{"7464926696447099909":1,"7486259459669820432":1}',
            "request_from": "profile_card_v2",
            "sec_anchor_id": "MS4wLjABAAAAiwBH59yM2i_loS11vwxZsudy4Bsv5L_EYIkYDmxgf-lv3oZL4YhQCF5oHQReiuUV",
            "request_from_scene": "1",
            "need_preload_room": "false",
            "target_uid": self.user_id,
            "anchor_id": "246047577136308224",
            "packed_level": "2",
            "need_block_status": "true",
            "current_room_id": "7521794357553400594",
            "device_platform": "android",
            "os": "android",
            "ssmix": "a",
            "_rticket": "1751311566864",
            "cdid": "808876f8-7328-4885-857d-8f15dd427861",
            "channel": "googleplay",
            "aid": "1233",
            "app_name": "musical_ly",
            "version_code": "370001",
            "version_name": "37.0.1",
            "manifest_version_code": "2023700010",
            "update_version_code": "2023700010",
            "ab_version": "37.0.1",
            "resolution": "720*1382",
            "dpi": "280",
            "device_type": "SM-A105F",
            "device_brand": "samsung",
            "language": "vi",
            "os_api": "30",
            "os_version": "11",
            "ac": "wifi",
            "is_pad": "0",
            "current_region": "VN",
            "app_type": "normal",
            "sys_region": "VN",
            "last_install_time": "1751308971",
            "timezone_name": "Asia/Baghdad",
            "residence": "VN",
            "app_language": "vi",
            "timezone_offset": "10800",
            "host_abi": "armeabi-v7a",
            "locale": "vi",
            "content_language": "vi,",
            "ac2": "wifi",
            "uoo": "1",
            "op_region": "VN",
            "build_number": "37.0.1",
            "region": "VN",
            "ts": "1751311566",
            "iid": "7521814657976928001",
            "device_id": "7405632852996097552",
            "openudid": "c79c40b21606bf59",
            "webcast_sdk_version": "3610",
            "webcast_language": "vi",
            "webcast_locale": "vi_VN",
            "es_version": "3",
            "effect_sdk_version": "17.6.0",
            "current_network_quality_info": '{"tcp_rtt":16,"quic_rtt":16,"http_rtt":584,"downstream_throughput_kbps":1400,"quic_send_loss_rate":-1,"quic_receive_loss_rate":-1,"net_effective_connection_type":3,"video_download_speed":1341}'
        }

        unsigned_params = get(params=params)

        cookies = {}
        for item in headers["cookie"].split(';'):
            if item.strip():
                try:
                    key, value = item.strip().split('=', 1)
                    cookies[key.strip()] = value.strip()
                except ValueError:
                    cookies[item.strip()] = ''

        signature = sign(params=unsigned_params, cookie=cookies)

        headers.update({
            'x-ss-req-ticket': signature['x-ss-req-ticket'],
            'x-ss-stub': signature['x-ss-stub'],
            'x-argus': signature["x-argus"],
            'x-gorgon': signature["x-gorgon"],
            'x-khronos': signature["x-khronos"],
            'x-ladon': signature["x-ladon"],
        })

        headers["accept-encoding"] = "identity"
        response = requests.get(url, headers=headers, params=unsigned_params)

        try:
            data = response.json()
            if data.get('status_code') != 0:
                self.lvl = ""
            else:
                if 'data' in data and 'badge_list' in data['data']:
                    badge_list = data['data']['badge_list']
                    for badge in badge_list:
                        combine = badge.get('combine', {})
                        if combine and 'text' in combine:
                            text = combine.get('text', {})
                            if 'default_pattern' in text:
                                self.lvl = text['default_pattern']
                            else:
                                self.lvl = ""
                        else:
                            self.lvl = ""
                else:
                    self.lvl = ""
        except json.JSONDecodeError:
            self.lvl = ""

    def analytics(self):
        url = "https://influencers.club/wp-json/tools/v1/proxy/analyzer/"
        headers = {
            'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36",
            'Content-Type': "application/json",
            'sec-ch-ua-platform': "\"Android\"",
            'sec-ch-ua': "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"",
            'sec-ch-ua-mobile': "?1",
            'origin': "https://d2dve41rwvcssr.cloudfront.net",
            'sec-fetch-site': "cross-site",
            'sec-fetch-mode': "cors",
            'sec-fetch-dest': "empty",
            'referer': "https://d2dve41rwvcssr.cloudfront.net/",
            'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7",
            'priority': "u=1, i"
        }

        payload = {"platform": "tiktok", "filter_key": "user", "filter_value": self.username}

        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            tiktok_data = data.get("tiktok", {})

            self.analytics_data = {
                "avg_likes": tiktok_data.get("avg_likes"),
                "engagement_rate": tiktok_data.get("engagement_rate"),
                "avg_views": tiktok_data.get("avg_views"),
                "avg_comments": tiktok_data.get("avg_comments"),
                "median_engagement_percent": tiktok_data.get("median_engagement_percent"),
                "min_engagement_percent": tiktok_data.get("min_engagement_percent"),
                "max_engagement_percent": tiktok_data.get("max_engagement_percent"),
                "tiktok_hashtags": tiktok_data.get("tiktok_hashtags", []),
                "follower_range": tiktok_data.get("follower_range", []),
                "total_likes": tiktok_data.get("total_likes"),
                "number_of_posts": tiktok_data.get("number_of_posts"),
                "posts_per_month": tiktok_data.get("posts_per_month"),
                "creator_growth": tiktok_data.get("creator_growth"),
                "follower_growth_90_days": tiktok_data.get("follower_growth_90_days"),
                "tagged": tiktok_data.get("tagged", []),
                "brands": tiktok_data.get("brands", [])
            }
        except:
            self.analytics_data = {}

def main():
    username = slow_input("Enter the username : ").strip()
    msg = []

    msg.append("━━━━━━━━━━━━━━━━━━━━━━")
    msg.append(f"📊 TikTok Full Account Information by @gqpgqpg — @{username}**")
    msg.append("━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        web = webaccountinfo(username)
        info = web.web_info

        msg.append("🌐 Web Info")
        for k, v in info.items():
            if isinstance(v, dict):
                msg.append(f"• {k.upper()}**")
                for sk, sv in v.items():
                    msg.append(f"   └ {sk} : {sv}")
            else:
                msg.append(f"• {k} : {v}")
    except:
        msg.append("🌐 Web Info — N/A")

    msg.append("\n━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        app = appaccountinfo(username, web.web_info["id"])
        msg.append("📱 App Info")
        msg.append(f"• Level : {app.lvl or 'N/A'}")
        msg.append(f"• Country : {app.country() or 'N/A'}")

        if app.analytics_data:
            for k, v in app.analytics_data.items():
                msg.append(f"• {k} : {v}")
        else:
            msg.append("• Analytics : N/A")
    except:
        msg.append("📱 App Info — N/A")
    msg.append("\n━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        sec = accountsecuirtyinfo(username)
        msg.append("🔐 Security Info")
        for k, v in sec.mess.items():
            msg.append(f"• {k} : {v}")
    except:
        msg.append("🔐 Security Info — N/A")

    msg.append("\n━━━━━━━━━━━━━━━━━━━━━━")

    print("\n".join(msg))

main()
    