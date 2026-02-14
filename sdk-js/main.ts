import { JsBroadcasters } from "./pkg/railgun_rs";
import { createWakuTransport } from "./src/waku-transport"

async function main() {
    const transport = await createWakuTransport();
    const broadcasters = new JsBroadcasters(1n, transport);
    await broadcasters.start();
}

main()
