import asyncio
import os
import uvicorn
import base64
import threading
import httpx
import json
import aiofiles
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware

from kademlia.network import Server

# --- Configuration (Unchanged) ---
NODE_PORT = int(os.getenv("NODE_PORT", 8468))
API_PORT = int(os.getenv("API_PORT", 8001))
BOOTSTRAP_IP = os.getenv("BOOTSTRAP_IP", None)
BOOTSTRAP_PORT = int(os.getenv("BOOTSTRAP_PORT", 8468))
OWN_PUBLIC_URL = os.getenv("OWN_PUBLIC_URL")
OWN_INTERNAL_URL = os.getenv("OWN_INTERNAL_URL")
STORAGE_PATH = "/storage"

app_state = {}

def run_kademlia_loop(loop, server, bootstrap_node):
    asyncio.set_event_loop(loop)
    async def start_and_bootstrap():
        await server.listen(NODE_PORT)
        print(f"Kademlia node running in background thread with ID: {server.node.id.hex()}")
        if bootstrap_node:
            print(f"Attempting to bootstrap to {bootstrap_node}...")
            # --- START OF MODIFICATION 1 ---
            # Give the network a moment to settle before bootstrapping
            await asyncio.sleep(5) 
            # --- END OF MODIFICATION 1 ---
            neighbors = await server.bootstrap([bootstrap_node])
            if neighbors:
                print(f"Bootstrap successful. Found {len(neighbors)} neighbors.")
            else:
                print("Bootstrap failed to find neighbors.")
    loop.run_until_complete(start_and_bootstrap())
    loop.run_forever()

@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(STORAGE_PATH, exist_ok=True)
    
    print("Starting Kademlia node in a background thread...")
    kademlia_loop = asyncio.new_event_loop()
    kademlia_server = Server()
    bootstrap_node = (BOOTSTRAP_IP, BOOTSTRAP_PORT) if BOOTSTRAP_IP else None
    kademlia_thread = threading.Thread(target=run_kademlia_loop, args=(kademlia_loop, kademlia_server, bootstrap_node), daemon=True)
    kademlia_thread.start()
    
    # --- START OF MODIFICATION 2 ---
    # Increase sleep time to allow the Kademlia thread to fully initialize and bootstrap
    await asyncio.sleep(10) 
    # --- END OF MODIFICATION 2 ---
    
    async def re_announce_data():
        print("Scanning local storage to re-announce data...")
        try:
            stored_files = os.listdir(STORAGE_PATH)
            if not stored_files:
                print("No existing data to re-announce.")
                return

            provider_info = { "public_url": OWN_PUBLIC_URL, "internal_url": OWN_INTERNAL_URL }
            provider_info_str = json.dumps(provider_info)
            
            for filename in stored_files:
                key = filename
                future = asyncio.run_coroutine_threadsafe(kademlia_server.set(key, provider_info_str), kademlia_loop)
                try:
                    future.result(timeout=10)
                except Exception as e:
                    print(f"    - Failed to re-announce key '{key[:10]}...': {e}")
            print("Re-announcement scan complete.")
        except Exception as e:
            print(f"Error during re-announcement: {e}")

    asyncio.create_task(re_announce_data())
    
    app_state["kademlia_server"] = kademlia_server
    app_state["kademlia_loop"] = kademlia_loop
    app_state["http_client"] = httpx.AsyncClient(timeout=10.0)
    print("P2P Node API is ready.")
    yield
    print("Shutting down...")
    await app_state["http_client"].aclose()
    kademlia_loop.call_soon_threadsafe(kademlia_loop.stop)
    print("Shutdown complete.")

# ... (rest of the file is unchanged) ...
app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://localhost:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Health Check and Debug Endpoints ---
@app.get("/health")
async def health_check():
    server = app_state.get("kademlia_server")
    if not server or not server.node:
        raise HTTPException(status_code=503, detail="Kademlia server is not running.")
    
    try:
        stored_shards_count = len(os.listdir(STORAGE_PATH))
    except Exception:
        stored_shards_count = -1
    
    return {
        "status": "ok",
        "kademlia_id": server.node.id.hex(),
        "known_peers": len(server.protocol.router.find_neighbors(server.node)),
        "stored_shards_count": stored_shards_count,
        "public_url": OWN_PUBLIC_URL
    }

# --- CORRECTED: Garbage Collection Endpoint ---
@app.post("/gc")
async def trigger_garbage_collection(active_hashes: List[str] = Body(...)):
    print("--- Starting Garbage Collection ---")
    # --- FIX: Use the global STORAGE_PATH constant directly ---
    storage_path = STORAGE_PATH
    
    try:
        locally_stored_files = set(os.listdir(storage_path))
        active_hashes_set = set(active_hashes)
        
        garbage_files = locally_stored_files - active_hashes_set
        
        if not garbage_files:
            print("No garbage found. Storage is clean.")
            return {"status": "no_garbage_found", "deleted_count": 0}

        print(f"Found {len(garbage_files)} garbage files to delete.")
        deleted_count = 0
        for filename in garbage_files:
            try:
                os.remove(os.path.join(storage_path, filename))
                deleted_count += 1
            except Exception as e:
                print(f"Could not delete file {filename}: {e}")
        
        print(f"--- Garbage Collection Complete. Deleted {deleted_count} files. ---")
        return {"status": "gc_complete", "deleted_count": deleted_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred during GC: {e}")

# --- (All other endpoints remain the same) ---
@app.get("/debug/list_keys")
async def list_keys():
    try:
        return {"locally_stored_keys": os.listdir(STORAGE_PATH)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read storage directory: {e}")

@app.post("/internal/store_share")
async def internal_store_share(data: dict = Body(...)):
    key = data.get("key")
    value = data.get("value")
    file_path = os.path.join(STORAGE_PATH, key)
    try:
        async with aiofiles.open(file_path, 'w') as f:
            await f.write(value)
        print(f"Locally stored share to file for key '{key[:10]}...'.")
        return {"status": "stored_locally"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write share to disk: {e}")

@app.get("/internal/get_share/{key}")
async def internal_get_share(key: str):
    file_path = os.path.join(STORAGE_PATH, key)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Share not found on this node's disk.")
    try:
        async with aiofiles.open(file_path, 'r') as f:
            value = await f.read()
        return {"key": key, "value": value}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read share from disk: {e}")

@app.post("/p2p/store")
async def store_data(data: dict = Body(...)):
    server = app_state.get("kademlia_server")
    loop = app_state.get("kademlia_loop")
    if not server or not loop: raise HTTPException(status_code=503, detail="Kademlia server not initialized")
    
    key = data.get("key")
    value = data.get("value")
    if not key or value is None:
        raise HTTPException(status_code=400, detail="Key and value are required.")

    try:
        await internal_store_share({"key": key, "value": value})
        
        provider_info = { "public_url": OWN_PUBLIC_URL, "internal_url": OWN_INTERNAL_URL }
        provider_info_str = json.dumps(provider_info)
        
        print(f"Announcing provider for key '{key[:10]}...' to the DHT.")
        future_set = asyncio.run_coroutine_threadsafe(server.set(key, provider_info_str), loop)
        future_set.result(timeout=15)
        print(f"Successfully announced provider for key '{key[:10]}...'.")

        print(f"Verifying storage for key '{key[:10]}...' on the DHT...")
        future_get = asyncio.run_coroutine_threadsafe(server.get(key), loop)
        verification_result = future_get.result(timeout=15)
        
        if verification_result is None:
            raise Exception("Verification failed; data could not be found on DHT after setting.")
        
        print(f"✅ Verification successful for key '{key[:10]}...'.")
        
        return {"status": "announced_and_verified", "provider": OWN_PUBLIC_URL}
    except Exception as e:
        print(f"ERROR during store: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to store or announce data: {e}")

@app.get("/p2p/get/{key}")
async def get_data(key: str):
    file_path = os.path.join(STORAGE_PATH, key)
    if os.path.exists(file_path):
        print(f"Found key '{key[:10]}...' in local file storage.")
        return await internal_get_share(key)

    server = app_state.get("kademlia_server")
    loop = app_state.get("kademlia_loop")
    client = app_state.get("http_client")
    if not server or not loop or not client: raise HTTPException(status_code=503, detail="Server not fully initialized")
    
    try:
        print(f"Key '{key[:10]}...' not found locally. Searching DHT for a provider...")
        future = asyncio.run_coroutine_threadsafe(server.get(key), loop)
        provider_info_str = future.result(timeout=15)
        
        if provider_info_str is None:
            raise HTTPException(status_code=404, detail="Provider for data not found on the DHT.")
        
        provider_info = json.loads(provider_info_str)
        provider_internal_url = provider_info.get("internal_url")
        
        print(f"Found provider for key '{key[:10]}...' at internal URL {provider_internal_url}.")
        
        if not provider_internal_url:
            raise HTTPException(status_code=500, detail="Provider info is malformed.")

        print(f"Contacting provider node at internal URL {provider_internal_url} to get data...")
        response = await client.get(f"{provider_internal_url}/internal/get_share/{key}")
        response.raise_for_status()
        return response.json()

    except Exception as e:
        print(f"ERROR during get: {e}")
        if isinstance(e, (asyncio.TimeoutError, httpx.TimeoutException)):
             raise HTTPException(status_code=404, detail=f"Data not found on the network (DHT/HTTP timeout).")
        raise HTTPException(status_code=500, detail=f"Failed to get data: {e}")

if __name__ == "__main__":
    uvicorn.run("p2p_node:app", host="0.0.0.0", port=API_PORT, log_level="info")