const { feishuRequest } = require('./client');

function resolveMessageText(message) {
  const content = message?.body?.content;
  if (!content) return '';
  try {
    const obj = JSON.parse(content);
    if (obj?.text) return String(obj.text);
  } catch {}
  return String(content);
}

async function listChatMessages({ userAccessToken, chatId, pageSize = 20, pageToken }) {
  const url = new URL('https://open.feishu.cn/open-apis/im/v1/messages');
  url.searchParams.set('container_id_type', 'chat');
  url.searchParams.set('container_id', chatId);
  url.searchParams.set('page_size', String(pageSize));
  if (pageToken) url.searchParams.set('page_token', String(pageToken));

  const json = await feishuRequest({
    method: 'GET',
    url: url.toString(),
    userAccessToken,
  });

  const items = (json?.data?.items || []).map((m) => ({
    messageId: m.message_id,
    createTime: m.create_time,
    senderId: m.sender?.id,
    senderIdType: m.sender?.id_type,
    msgType: m.msg_type,
    text: resolveMessageText(m),
    raw: m,
  }));

  return {
    items,
    hasMore: Boolean(json?.data?.has_more),
    pageToken: json?.data?.page_token || null,
    raw: json,
  };
}

async function sendTextMessageToChat({ userAccessToken, chatId, text }) {
  const url = new URL('https://open.feishu.cn/open-apis/im/v1/messages');
  url.searchParams.set('receive_id_type', 'chat_id');

  const body = {
    receive_id: chatId,
    msg_type: 'text',
    content: JSON.stringify({ text }),
  };

  const json = await feishuRequest({
    method: 'POST',
    url: url.toString(),
    userAccessToken,
    body,
  });

  return json;
}

module.exports = {
  listChatMessages,
  sendTextMessageToChat,
};

