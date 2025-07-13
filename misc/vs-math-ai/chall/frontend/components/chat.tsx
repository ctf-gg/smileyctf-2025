"use client";

import { useChat, type Message } from "@ai-sdk/react";

import { ChatList } from "@/components/chat-list";
import { ChatPanel } from "@/components/chat-panel";
import { ChatScrollAnchor } from "@/components/chat-scroll-anchor";
import { EmptyScreen } from "@/components/empty-screen";
import { cn } from "@/lib/utils";
import { toast } from "react-hot-toast";
import { useEffect, useState } from "react";

export interface ChatProps extends React.ComponentProps<"div"> {
	initialMessages?: Message[];
	id?: string;
}

export function Chat({ id, initialMessages, className }: ChatProps) {
	const [limitReached, setLimitReached] = useState(false);
	const { messages, append, reload, stop, isLoading, input, setInput } =
		useChat({
			initialMessages,
			id,
			body: {
				id,
			},
			onResponse(response) {
				if (response.status === 401) {
					toast.error(response.statusText);
				}
			},
		});

	useEffect(() => {
		if (messages.length >= 20 && messages[messages.length - 1]?.role === "assistant" && messages[messages.length - 1].content) {
			setLimitReached(true);
		}
	}, [messages]);
	return (
		<>
			<div className={cn("pb-[200px] pt-4 md:pt-10", className)}>
				{messages.length ? (
					<>
						<ChatList messages={messages} />
						<ChatScrollAnchor trackVisibility={isLoading} />
					</>
				) : (
					<EmptyScreen setInput={setInput} />
				)}
			</div>
			<ChatPanel
				id={id}
				isLoading={isLoading}
				stop={stop}
				append={append}
				reload={reload}
				messages={messages}
				input={input}
				setInput={setInput}
				isLimitReached={limitReached}
			/>
		</>
	);
}
