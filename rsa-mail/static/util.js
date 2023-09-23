function parse_message(text) {
	let bodystart = text.indexOf('\n\n');
	if (bodystart == -1) {
		return undefined;
	}
	let headers = text.substring(0, bodystart);
	let body = text.substring(bodystart + 2);

	let headerlines = headers.split('\n');
	var sender = '';
	var subject = '';
	var date = '';

	headerlines.forEach(line => {
		if (line.startsWith('FROM: ')) {
			sender = line.substring(6)
		}
		if (line.startsWith('DATE: ')) {
			date = line.substring(6)
		}
		if (line.startsWith('SUBJECT: ')) {
			subject = line.substring(9)
		}
	});

	return [sender, date, subject, body];
}

function format_message(account, subject, msg) {
	return `FROM: ${account}
DATE: ${new Date().toLocaleDateString('en-GB', {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
})}
SUBJECT: ${subject}

${msg}`;
}

function hex(x) {
	var r = "";
	x.forEach(digit => {
		r += digit.toString(16).padStart(2, '0');
	});
	return r;
}

function unhex(x) {
	var r = [];
	for (let i = 0; i + 1 < x.length; i += 2) {
		r.push(parseInt(x[i], 16) * 16 + parseInt(x[i + 1], 16));
	}
	return r;
}
