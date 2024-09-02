"""cros proxy server"""

import json
import logging

import aiohttp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from fastapi.responses import Response

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TARGET_HOST = "https://dev-api.waas.myabcwallet.com"


log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


@app.get("/{full_path:path}")
@app.post("/{full_path:path}")
@app.put("/{full_path:path}")
@app.delete("/{full_path:path}")
@app.patch("/{full_path:path}")
async def proxy(full_path: str, request: Request):
    """
    Proxies incoming requests to the target host, preserving the method, headers, body, and query parameters.

    Args:
        full_path (str): The path of the incoming request to be appended to the target host URL.
        request (Request): The incoming FastAPI request object.

    Returns:
        Response: The response received from the target host, forwarded back to the client.
    """
    log.info("Proxying request to %s/%s", TARGET_HOST, full_path)
    headers = dict(request.headers)
    log.info("Headers: %s", json.dumps(headers, indent=4))

    async with aiohttp.ClientSession() as session:
        url = f"{TARGET_HOST}/{full_path}"
        body = await request.body()
        params = dict(request.query_params)

        async with session.request(
            method=request.method, url=url, headers=headers, data=body, params=params
        ) as resp:
            response_body = await resp.read()
            return Response(
                content=response_body,
                status_code=resp.status,
                headers=dict(resp.headers),
            )
