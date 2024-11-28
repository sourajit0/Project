from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import List, Dict
import hashlib
import datetime
import asyncio
import httpx

# FastAPI application and basic security
app = FastAPI()
security = HTTPBasic()

# Admin credentials for authentication
AUTHORIZED_USER = {"username": "admin", "password": "admin123"}

# Hardcoded nodes (other blockchain nodes to sync with)
NODES = [
    "http://141.148.210.10",
    "http://129.154.241.21"
]

# Data structures
blockchain: List[Dict] = []

# Genesis block creation
def create_genesis_block():
    genesis_block = {
        "index": 1,
        "previous_hash": "0",
        "timestamp": datetime.datetime.now().timestamp(),
        "data": {},
        "hash": hashlib.sha256(str("0").encode()).hexdigest(),
    }
    blockchain.append(genesis_block)

create_genesis_block()

# Helper function to create new blocks
def create_block(data: dict):
    previous_block = blockchain[-1]
    index = previous_block["index"] + 1
    timestamp = datetime.datetime.now().timestamp()
    previous_hash = previous_block["hash"]
    block_hash = hashlib.sha256(
        f"{index}{previous_hash}{timestamp}{data}".encode()
    ).hexdigest()
    return {
        "index": index,
        "previous_hash": previous_hash,
        "timestamp": timestamp,
        "data": data,
        "hash": block_hash,
    }

# Validate a block (check its index and hash integrity)
def validate_block(block: Dict, previous_block: Dict):
    if block["index"] != previous_block["index"] + 1:
        return False
    if block["previous_hash"] != previous_block["hash"]:
        return False
    calculated_hash = hashlib.sha256(
        f"{block['index']}{block['previous_hash']}{block['timestamp']}{block['data']}".encode()
    ).hexdigest()
    return block["hash"] == calculated_hash

# Pydantic models for Voter and Candidate
class Voter(BaseModel):
    voter_id: str
    name: str
    password: str  # Include password in the model

class Candidate(BaseModel):
    candidate_id: str
    name: str

# Endpoints

@app.get("/chain")
async def get_chain():
    return blockchain

@app.post("/register_voter")
async def register_voter(voter: Voter, credentials: HTTPBasicCredentials = Depends(security)):
    # Authenticate admin credentials
    if credentials.username != AUTHORIZED_USER["username"] or credentials.password != AUTHORIZED_USER["password"]:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Check for unique voter ID in blockchain
    for block in blockchain:
        if block["data"].get("type") == "voter" and block["data"].get("voter_id") == voter.voter_id:
            raise HTTPException(status_code=400, detail="Voter already exists")

    # Add a block for voter registration with password included
    data = {"type": "voter", "voter_id": voter.voter_id, "name": voter.name, "password": voter.password}
    new_block = create_block(data)
    blockchain.append(new_block)

    # Broadcast the new block to other nodes
    await broadcast_block(new_block)

    return {
        "message": "Voter registered successfully",
        "voter_id": voter.voter_id,
        "block": new_block,
    }

@app.post("/register_candidate")
async def register_candidate(candidate: Candidate, credentials: HTTPBasicCredentials = Depends(security)):
    # Authenticate admin credentials
    if credentials.username != AUTHORIZED_USER["username"] or credentials.password != AUTHORIZED_USER["password"]:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Check for unique candidate ID in blockchain
    for block in blockchain:
        if block["data"].get("type") == "candidate" and block["data"].get("candidate_id") == candidate.candidate_id:
            raise HTTPException(status_code=400, detail="Candidate already exists")

    # Add a block for candidate registration
    data = {"type": "candidate", "candidate_id": candidate.candidate_id, "name": candidate.name}
    new_block = create_block(data)
    blockchain.append(new_block)

    # Broadcast the new block to other nodes
    await broadcast_block(new_block)

    return {
        "message": "Candidate registered successfully",
        "block": new_block,
    }

@app.post("/cast_vote")
async def cast_vote(voter_id: str, password: str, candidate_id: str):
    # Check if the voter exists in blockchain and password is correct
    voter_found = False
    for block in blockchain:
        if block["data"].get("type") == "voter" and block["data"].get("voter_id") == voter_id:
            if block["data"].get("password") == password:
                voter_found = True
            break

    if not voter_found:
        raise HTTPException(status_code=401, detail="Invalid voter ID or password")
    
    # Check if the voter has already voted
    for block in blockchain:
        if block["data"].get("type") == "vote" and block["data"].get("voter_id") == voter_id:
            raise HTTPException(status_code=400, detail="Voter has already cast their vote")

    # Check if candidate ID is valid
    candidate_found = False
    for block in blockchain:
        if block["data"].get("type") == "candidate" and block["data"].get("candidate_id") == candidate_id:
            candidate_found = True
            break

    if not candidate_found:
        raise HTTPException(status_code=400, detail="Invalid candidate ID")
    
    # Register the vote by adding it to the blockchain
    data = {"type": "vote", "voter_id": voter_id, "candidate_id": candidate_id}
    new_block = create_block(data)
    blockchain.append(new_block)

    # Broadcast the new block to other nodes
    await broadcast_block(new_block)

    return {
        "message": "Vote cast successfully",
        "block": new_block,
    }

@app.get("/show_results")
async def show_results():
    # Count the votes for each candidate by scanning the blockchain
    results = {}
    
    # Traverse through the blockchain and collect vote counts
    for block in blockchain:
        if block["data"].get("type") == "vote":
            candidate_id = block["data"].get("candidate_id")
            candidate_name = None
            for candidate_block in blockchain:
                if candidate_block["data"].get("type") == "candidate" and candidate_block["data"].get("candidate_id") == candidate_id:
                    candidate_name = candidate_block["data"].get("name")
                    break
            if candidate_name:
                if candidate_name not in results:
                    results[candidate_name] = 0
                results[candidate_name] += 1
    
    return {"results": results}

@app.post("/receive_block")
async def receive_block(block: Dict):
    # Validate and add received block
    if not blockchain or block["index"] == 1:  # Genesis block
        blockchain.append(block)
        return {"message": "Genesis block received"}

    previous_block = blockchain[-1]
    if validate_block(block, previous_block):
        blockchain.append(block)
        return {"message": "Block added successfully"}
    else:
        raise HTTPException(status_code=400, detail="Invalid block")

@app.post("/sync_chain")
async def sync_chain():
    async with httpx.AsyncClient() as client:
        tasks = [client.get(f"{node}/chain") for node in NODES]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        longest_chain = blockchain
        for response in responses:
            if isinstance(response, httpx.Response) and response.status_code == 200:
                node_chain = response.json()
                if len(node_chain) > len(longest_chain):
                    longest_chain = node_chain
        
        if len(longest_chain) > len(blockchain):
            blockchain.clear()
            blockchain.extend(longest_chain)
            return {"message": "Chain synced with longest chain"}
        return {"message": "Local chain is already the longest"}

async def broadcast_block(block: Dict):
    async with httpx.AsyncClient() as client:
        tasks = [client.post(f"{node}/receive_block", json=block) for node in NODES]
        await asyncio.gather(*tasks, return_exceptions=True)
