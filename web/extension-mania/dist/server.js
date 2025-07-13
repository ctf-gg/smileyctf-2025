import config from "./config.js";
import express from 'express';
import * as bot from "./bot.js";

import fs from "fs";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

let customHtml = fs.readFileSync("templates/default.html", "utf8");

app.get('/', (req, res) => {
    if(req.get("Host") == config.host || req.get("Host") == config.host + ":" + config.port){
        res.send(customHtml);
    }else{
        res.sendFile("templates/update.html", { root: process.cwd() });
        return;
    }
});

app.post('/bot', async (req, res) => {
    let [canRun, message] = bot.canRunBot();
    if(!canRun){
        res.status(403).send(message);
        return;
    }
    if(!req.body.url){
        res.status(400).send("No URL provided");
        return;
    }
    bot.runBot(req.body.url);
    res.status(200).send('Bot is running');
});

app.post("/update", (req, res) => {
    if(req.body.html){
        customHtml = req.body.html
        res.send("Updated!");
    } else {
        res.status(400).send("No HTML provided");
    }
});

app.get("/bot/status", (req, res) => {
    if(bot.shouldFlag()){
        res.json(process.env.FLAG || ".;,;.{placeholder_flag}");
    }else{
        res.json(bot.canRunBot());
    }
});

app.get("/page_content", (req, res) => {
    res.json(customHtml);
})

app.listen(config.port, () => {
    console.log(`Server is running on port ${config.port}`);
});

process.on("uncaughtException", console.warn);
process.on("unhandledRejection", console.warn);