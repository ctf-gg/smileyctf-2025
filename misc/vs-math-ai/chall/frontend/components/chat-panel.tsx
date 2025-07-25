import { type UseChatHelpers } from "ai/react";

import { ButtonScrollToBottom } from "@/components/button-scroll-to-bottom";
import { PromptForm } from "@/components/prompt-form";
import { Button } from "@/components/ui/button";
import { IconRefresh, IconStop } from "@/components/ui/icons";

export interface ChatPanelProps
	extends Pick<
		UseChatHelpers,
		| "append"
		| "isLoading"
		| "reload"
		| "messages"
		| "stop"
		| "input"
		| "setInput"
	> {
	id?: string;
	isLimitReached: boolean;
}

export function ChatPanel({
	id,
	isLoading,
	stop,
	append,
	reload,
	input,
	setInput,
	messages,
	isLimitReached
}: ChatPanelProps) {
	return (
		<div className="fixed inset-x-0 bottom-0">
			<ButtonScrollToBottom />
			<div className="mx-auto sm:max-w-2xl sm:px-4">
				<div className="flex h-10 items-center justify-center">
					{isLoading ? (
						<Button
							variant="outline"
							onClick={() => stop()}
							className="bg-background"
						>
							<IconStop className="mr-2" />
							Stop generating
						</Button>
					) : (
						messages?.length > 0 && (
							<Button
								variant="outline"
								onClick={() => reload()}
								className="bg-background"
							>
								<IconRefresh className="mr-2" />
								Regenerate response
							</Button>
						)
					)}
				</div>
				<div className="space-y-4 border-t bg-background px-4 py-2 shadow-lg sm:rounded-t-xl sm:border md:py-4">
					<PromptForm
						onSubmit={async (value) => {
							await append({
								id,
								content: value,
								role: "user",
							});
						}}
						input={input}
						setInput={setInput}
						isLoading={isLoading}
						isLimitReached={isLimitReached}
					/>
				</div>
			</div>
		</div>
	);
}
