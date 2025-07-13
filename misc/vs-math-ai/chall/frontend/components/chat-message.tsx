import React from 'react';
import { Message } from "ai";

import rehypeKatex from 'rehype-katex';
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";

import { ChatMessageActions } from "@/components/chat-message-actions";
import { MemoizedReactMarkdown } from "@/components/markdown";
import { CodeBlock } from "@/components/ui/codeblock";
import { IconUser, IconSpinner, IconCheck } from "@/components/ui/icons";
import { BotMessageSquare } from 'lucide-react';
import { cn } from "@/lib/utils";

import 'katex/dist/katex.min.css';

export interface ChatMessageProps {
	message: Message;
}

interface RenderableTextPart {
	type: 'text';
	content: string;
	id: string;
}

interface RenderableToolIndicatorPart {
	type: 'tool_indicator';
	id: string;
	toolCallId: string;
	toolName: string;
}

type RenderablePart = RenderableTextPart | RenderableToolIndicatorPart;

type MessagePart = Message['parts'] extends (infer P)[] ? P : never;

export function ChatMessage({ message, ...props }: ChatMessageProps) {
	const renderableParts: RenderablePart[] = [];
	let currentTextBuffer = "";

	if (message.parts && message.parts.length > 0) {
		message.parts.forEach((part, index) => {
			if (typeof part !== 'object' || part === null || typeof part.type !== 'string') {
				console.warn('Skipping malformed message part:', part);
				return;
			}

			if (part.type === 'text') {
				currentTextBuffer += (part as { text: string }).text;
			} else if (part.type === 'tool-invocation') {
				if (currentTextBuffer) {
					renderableParts.push({ type: 'text', content: currentTextBuffer, id: `text-${index}-pre` });
					currentTextBuffer = "";
				}
				const toolInvocationData = (part as any).toolInvocation || part;
				renderableParts.push({
					type: 'tool_indicator',
					id: `tool-${index}`,
					toolCallId: toolInvocationData.toolCallId,
					toolName: toolInvocationData.toolName,
				});
			}
		});

		if (currentTextBuffer) {
			renderableParts.push({ type: 'text', content: currentTextBuffer, id: `text-final` });
		}
	} else if (message.content) {
		renderableParts.push({ type: 'text', content: message.content, id: 'text-legacy' });
	}

	return (
		<div
			className={cn("group relative mb-4 flex items-start md:-ml-12")}
			{...props}
		>
			<div
				className={cn(
					"flex h-8 w-8 shrink-0 select-none items-center justify-center rounded-md border shadow",
					message.role === "user"
						? "bg-background"
						: "bg-primary text-primary-foreground",
				)}
			>
				{message.role === "user" ? <IconUser /> : <BotMessageSquare />}
			</div>
			<div className="flex-1 px-1 ml-4 space-y-2 overflow-hidden">
				{renderableParts.map(renderPart => {
					if (renderPart.type === 'text') {
						if (!renderPart.content.trim()) {
							return null;
						}
						return (
							<MemoizedReactMarkdown
								key={renderPart.id}
								remarkPlugins={[
									remarkGfm,
									[remarkMath],
								]}
								rehypePlugins={[rehypeKatex]}
								components={{
									p({ children }) {
										return <p className="mb-2 last:mb-0">{children}</p>;
									},
									code({ node, className, children, ...props }) {
										const childArray = React.Children.toArray(children);
										if (childArray.length > 0) {
											const firstChild = childArray[0];
											if (typeof firstChild === 'string' && firstChild === "▍") {
												return (
													<span className="mt-1 cursor-default animate-pulse">▍</span>
												);
											}
											if (typeof firstChild === 'string') {
												childArray[0] = firstChild.replace("`▍`", "▍");
											}
										}

										const match = /language-(\w+)/.exec(className || "");
										const isInline = !className;

										if (isInline) {
											return (
												<code className={className} {...props}>
													{children}
												</code>
											);
										}

										return (
											<CodeBlock
												key={Math.random()}
												language={(match && match[1]) || ""}
												value={String(children).replace(/\n$/, "")}
												{...props}
											/>
										);
									},
								}}
							>
								{renderPart.content}
							</MemoizedReactMarkdown>
						);
					} else if (renderPart.type === 'tool_indicator') {
						const toolResultPart = message.parts?.find(p => {
							if (p.type === 'tool-invocation') {
								const invocation = (p as any).toolInvocation || p;
								return (
									invocation.toolCallId === renderPart.toolCallId &&
									(invocation.state === 'result' || typeof invocation.result !== 'undefined')
								);
							}
							return false;
						}) as MessagePart | undefined;

						let statusIcon = <IconSpinner className="h-4 w-4 animate-spin" />;
						let statusText = "Working on it...";
						let textColor = "text-muted-foreground";

						if (toolResultPart) {
							statusIcon = <IconCheck className="h-4 w-4 text-green-500" />;
							statusText = "Task completed.";
							textColor = "text-green-500";
						}

						return (
							<div
								key={renderPart.id}
								className={`flex items-center gap-2 ${textColor} mb-2`}
							>
								{statusIcon}
								<span>{statusText}</span>
							</div>
						);
					}
					return null;
				})}
				<ChatMessageActions message={message} />
			</div>
		</div>
	);
}
