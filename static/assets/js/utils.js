function convertUTCtoLocal(utcTimestamp) {
    // Parse the UTC timestamp string
    const date = new Date(utcTimestamp);

    // Options for formatting the local date-time
    const options = {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    };

    // Convert to local date-time string
    const localDateTime = date.toLocaleString('en-US', options);

    return localDateTime;
}