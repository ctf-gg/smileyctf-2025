"use client";

import { Chat } from "@/components/chat";
import { TooltipProvider } from "@/components/ui/tooltip";
import { nanoid } from "nanoid";

export default function Page() {
	return (
		<TooltipProvider>
			<Chat id={nanoid()}></Chat>
		</TooltipProvider>
	);
}

Page.theme = 'dark'