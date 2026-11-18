--!strict

tern.route.link(function(link, cx)
    if not link.pane or not link.url:match("^https?://") or not link.url:match("[?&]redirect_uri=") then
        return nil
    end

    local host = cx.hosts:current()
    if host.kind ~= "local" or not table.find(host.panes, link.pane) then
        return nil
    end

    local url = link.url
    tern.process.run({ "tern", "process", string.format("%.0f", link.pane), "--json" }, function(result, window)
        if not window then return end
        local process = if result.status == 0 then tern.json.decode(result.stdout) else nil
        local foreground = process and process.foreground
        if type(foreground) ~= "table" or type(foreground.pid) ~= "number" then
            window:open(url)
            return
        end

        tern.process.run({ "agent-sandbox-dbus-proxy", "open", tostring(foreground.pid), url }, function(opened, current)
            if not current then return end
            if opened.status == 3 then
                current:open(url)
            elseif opened.status ~= 0 then
                current:toast("error", "Could not open sandbox OAuth link", opened.stderr)
            end
        end)
    end)
    return { handled = true }
end)
