import type { Metadata } from "next";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";

const jbm = JetBrains_Mono({ subsets: ["latin"] });

export const metadata: Metadata = {
	title: "vsMathAI",
	description: "vsMathAI: the superior solution for getting your math homework done",
};

export default function RootLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	return (
		<html lang="en">
			<body className={jbm.className + " dark"}>{children}</body>
		</html>
	);
}
