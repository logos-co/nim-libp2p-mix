local nimble_bin = vim.fn.expand("~/.nimble/bin")

vim.lsp.config("nim_langserver", {
  cmd = { nimble_bin .. "/nimlangserver" },
  capabilities = {
    workspace = {
      configuration = false,
    },
  },
  settings = {
    nim = {
      nimsuggestPath = vim.fn.expand("~/.nimble/bin/nimsuggest"),
      projectMapping = {
        {
          projectFile = "examples/mix_ping.nim",
          fileRegex = "^examples/mix_ping[.]nim$",
        },
        {
          projectFile = "libp2p_mix.nim",
          fileRegex = "^(libp2p_mix[.]nim|libp2p_mix/.*[.]nim)$",
        },
      },
    },
  },
})
