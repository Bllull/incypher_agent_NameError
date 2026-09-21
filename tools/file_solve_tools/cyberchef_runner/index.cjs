const fs = require("fs");
const chef = require("cyberchef");

async function main() {
  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  const input = Buffer.from(request.input_b64, "base64");
  const dish = await chef.bake(input, request.recipe);
  const value = dish.value;
  let result;

  if (Buffer.isBuffer(value)) {
    result = { encoding: "base64", value: value.toString("base64") };
  } else if (value instanceof ArrayBuffer) {
    result = { encoding: "base64", value: Buffer.from(value).toString("base64") };
  } else if (ArrayBuffer.isView(value)) {
    result = { encoding: "base64", value: Buffer.from(value.buffer).toString("base64") };
  } else {
    result = { encoding: "json", value: value };
  }

  process.stdout.write(JSON.stringify({ type: dish.type, result: result }));
}

main().catch((error) => {
  process.stderr.write(String((error && error.stack) || error));
  process.exitCode = 1;
});
