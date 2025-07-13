"use client";

import { type Message } from "ai";

import { Button } from "@/components/ui/button";
import { IconCheck, IconCopy } from "@/components/ui/icons";
import { useCopyToClipboard } from "@/lib/hooks/use-copy-to-clipboard";
import { cn } from "@/lib/utils";

interface ChatMessageActionsProps extends React.ComponentProps<"div"> {
	message: Message;
}

export function ChatMessageActions({
	message,
	className,
	...props
}: ChatMessageActionsProps) {
	const { isCopied, copyToClipboard } = useCopyToClipboard({ timeout: 2000 });

	const getMessageText = () => {
		if (!message.parts) {
			return message.content || '';
		}

		const textParts = message.parts
			.filter(part => part.type === 'text')
			.map(part => 'text' in part ? part.text : '')
			.join('');

		return textParts;
	};

	const onCopy = () => {
		if (isCopied) return;
		copyToClipboard(getMessageText());
	};

	return (
		<div
			className={cn(
				"flex items-center justify-end transition-opacity group-hover:opacity-100 md:absolute md:-right-10 md:-top-2 md:opacity-0",
				className,
			)}
			{...props}
		>
			<Button variant="ghost" size="icon" onClick={onCopy}>
				{isCopied ? <IconCheck /> : <IconCopy />}
				<span className="sr-only">Copy message</span>
			</Button>
		</div>
	);
}
