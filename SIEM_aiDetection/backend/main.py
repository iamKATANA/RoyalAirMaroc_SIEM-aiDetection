from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
import asyncio
import json
import cohere
from collections import defaultdict

cohere_client = cohere.Client("C5XFEHfVicXYUGVSquAoydcRxvidNmRIGBRPR8ry")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logs_df = pd.read_csv("backend/security_logs_royalairmaroc_melange.csv")
logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'], errors='coerce')
logs_df = logs_df.dropna(subset=['timestamp'])
logs_df['Hour'] = logs_df['timestamp'].dt.hour
logs_df['username_clean'] = (
    logs_df['username']
    .astype(str)
    .str.extract(r"([^@]+)")[0]
    .str.lower()
    .str.replace(r"[^\w]", ".", regex=True)
)

def train_model(df):
    df['Label'] = df['threat_level'].apply(lambda x: 1 if x == 'high' else 0)
    X = df[['Hour', 'event_type', 'action', 'status', 'protocol']].copy()
    y = df['Label']

    encoders = {}
    for col in ['event_type', 'action', 'status', 'protocol']:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        encoders[col] = le

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_scaled, y)
    return model, scaler, encoders

model, scaler, encoders = train_model(logs_df)

user_anomalies = defaultdict(list)
all_users = set(logs_df['username_clean'].dropna().unique())
for user in all_users:
    user_anomalies[user] = []


@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    port_scores = defaultdict(int) 
    for _, row in logs_df.iterrows():
        ip = row['src_ip']
        port = row.get('port', 'N/A')
        user = row['username_clean'] if pd.notna(row['username_clean']) else "inconnu"
        {
  "type": "ports",
  "ports": [
    {"port": "80", "score": 10},
    {"port": "443", "score": 75},
    {"port": "22", "score": 90}
  ]
}


        ip_score = int(hash(ip) % 100)

        try:
            features = [
                int(row['Hour']),
                encoders['event_type'].transform([str(row['event_type'])])[0],
                encoders['action'].transform([str(row['action'])])[0],
                encoders['status'].transform([str(row['status'])])[0],
                encoders['protocol'].transform([str(row['protocol'])])[0],
            ]
        except:
            continue

        scaled = scaler.transform([features])
        pred = model.predict(scaled)[0]

        criticity = 0
        if ip_score >= 50:
            criticity += 50
        if pred == 1:
            criticity += 50

        if criticity == 0:
            level = "normal"
        elif criticity < 50:
            level = "anomaly_low"
        elif 50 <= criticity < 100:
            level = "anomaly_medium"
        else:
            level = "anomaly_high"

        if level != "normal":
            user_anomalies[user].append({
                "timestamp": str(row['timestamp']),
                "ip": ip,
                "action": row['action'],
                "port": str(port),
                "level": level
            })

        port_display = f"<b>{port}</b>" if level in ["anomaly_medium", "anomaly_high"] else port
        message = f"{row['timestamp']} - {ip} - Action: {row['action']} - Port: {port_display} - Criticité: {level}"

        await websocket.send_text(json.dumps({
            "type": "log",
            "timestamp": str(row['timestamp']),
            "ip": ip,
            "score": int(ip_score),
            "action": str(row['action']),
            "port": str(port),
            "level": level,
            "message": message
        }))

        all_ranked = sorted(user_anomalies.items(), key=lambda x: len(x[1]), reverse=True)
        await websocket.send_text(json.dumps({
            "type": "ranking",
            "ranking": [
        {"username": u, "count": len(logs)} for u, logs in all_ranked
            ]
        }))

        

        await websocket.send_text(json.dumps({
            "type": "critical",
            "username": user,
            "ip": ip,
            "port": str(port),
            "timestamp": str(row['timestamp']),
            "action": row['action']
        }))
        if level == "anomaly_high":
            try:
                p = int(port)
                port_scores[p] += 25
            except:
                pass

        await websocket.send_text(json.dumps({
    "type": "ports",
    "ports": [{"port": str(k), "score": v} for k, v in port_scores.items()]
}))
        await websocket.send_text(json.dumps({
    "type": "ports",
    "ports": [{"port": str(k), "score": v} for k, v in port_scores.items()]
}))


        await asyncio.sleep(0.4)

@app.get("/details/{username}")
async def get_user_details(username: str):
    user_logs = logs_df[logs_df["username_clean"] == username]
    if user_logs.empty:
        return {"details": f"Aucune donnée trouvée pour {username}"}
    return {"details": user_logs.to_dict(orient="records")}



@app.get("/user/{username}")
def get_user_details(username: str):
    return {"details": user_anomalies.get(username, [])}

@app.get("/analyze/{username}")
def analyze_user_logs(username: str):
    logs = user_anomalies.get(username, [])
    if not logs:
        return {"analysis": "Aucune donnée d'anomalie pour cet utilisateur."}

    logs_text = "\n".join([
        f"{l['timestamp']} | {l['ip']} | {l['action']} | Port: {l['port']} | {l['level']}" for l in logs
    ])

    prompt = (
        f"Voici les logs suspects d'un utilisateur :\n{logs_text}\n\n"
        f"Réponds avec une structure claire contenant 3 parties :\n"
        f"🤖 **Analyse IA pour {username}**\n\n"
        f"🔍 **Actions :**\n- Liste claire des actions observées\n\n"
        f"⚠️ **Attaque possible :**\n- Hypothèses sur les types d'attaques possibles\n\n"
        f"🛡️ **Mesures de sécurité :**\n- Recommandations pratiques de sécurité. écris les recommendation sans rien ajouter en bas"
    )

    try:
        response = cohere_client.chat(
            model="command-r-plus",
            message=prompt,
            temperature=0.4
        )
        return {"analysis": response.text}
    except Exception as e:
        return {"analysis": f"Erreur IA : {str(e)}"}

class ChatPrompt(BaseModel):
    question: str
    logs_context: list[str] = []

@app.post("/chat")
def chatbot(prompt: ChatPrompt):
    context = "\n".join(prompt.logs_context[-10:])
    question = prompt.question

    try:
        response = cohere_client.chat(
            model="command-r-plus",
            message=f"Voici les logs récents :\n{context}\n\nQuestion : {question}\nRéponse :",
            temperature=0.5
        )
        return {"response": response.text}
    except Exception as e:
        return {"response": f" Erreur IA : {str(e)}"}
    
