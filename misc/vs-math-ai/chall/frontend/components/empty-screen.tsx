import { UseChatHelpers } from "@ai-sdk/react";

import { Button } from "@/components/ui/button";
import { IconArrowRight } from "@/components/ui/icons";

const exampleMessages = [
	{
		heading: "2 + 2",
		message: `what is 2 + 2?`,
	},
];

export function EmptyScreen({ setInput }: Pick<UseChatHelpers, "setInput">) {
	return (
		<div className="mx-auto max-w-2xl px-4">
			<div className="rounded-lg border bg-background p-8">
				<h1 className="mb-2 text-lg font-semibold">
					welcome to <span className="text-transparent bg-clip-text bg-gradient-to-r from-orange-500 to-orange-400">vs math ai</span>, the superior solution for getting your math
					homework done
				</h1>
				<p className="leading-normal text-muted-foreground">
					ask a math question or try out these examples:
				</p>
				<div className="mt-4 flex flex-col items-start space-y-2">
					{exampleMessages.map((message, index) => (
						<Button
							key={index}
							variant="link"
							className="h-auto p-0 text-base"
							onClick={() => setInput(message.message)}
						>
							<IconArrowRight className="mr-2 text-muted-foreground" />
							{message.heading}
						</Button>
					))}
				</div>
			</div>
		</div>
	);
}
